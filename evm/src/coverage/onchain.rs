//! Per-address on-chain coverage reports.
//!
//! When recon is run with `--rpc-url` and a `--corpus-dir`, every external
//! contract whose code the fork actually pulled from RPC is treated as a
//! first-class coverage target. We mirror echidna's flow exactly:
//!
//! 1. After the campaign, iterate the fork's contract cache.
//! 2. For each address, fetch the verified source: try Sourcify first
//!    (no API key needed) and fall back to Etherscan v2 (requires the
//!    `ETHERSCAN_API_KEY` env var).
//! 3. Etherscan's JSON API doesn't expose runtime source maps, so when we
//!    fall back to Etherscan we additionally HTML-scrape the address page
//!    on the relevant block explorer to recover the source map (matching
//!    echidna `Onchain/Etherscan.hs:fetchContractSourceMap`).
//! 4. Build a `ContractSourceInfo` from the deployed bytecode + source map,
//!    then reuse the existing `SourceCoverage` writer to emit
//!    `<corpus>/<addr>/covered.<unix_ts>.{html,lcov}`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{keccak256, Address, B256, Bytes};
use serde::Deserialize;

use super::source::{
    parse_source_map, save_html_report, save_lcov_report, ContractSourceInfo, FileCoverage,
    SourceCoverage, SourceFile, SourceMap,
};

/// Unified verified-source description for an external contract. Mirrors
/// echidna's `Onchain.Types.SourceData`.
#[derive(Debug, Clone)]
pub struct OnchainSource {
    /// Contract name, e.g. `"StableSwap"`.
    pub contract_name: String,
    /// Map of source file path → file content. Each entry becomes one of the
    /// files the coverage report renders.
    pub files: HashMap<String, String>,
    /// Source map for the deployed (runtime) bytecode.
    pub runtime_src_map: String,
}

/// Errors from on-chain source fetching. We never propagate these — failures
/// are best-effort and fall back to the next source (Sourcify → Etherscan →
/// nothing). The variants exist mostly so logs are useful.
#[derive(Debug)]
pub enum OnchainSourceError {
    Network(String),
    Decode(String),
    NotVerified,
    NoSourceMap,
    NoApiKey,
}

impl std::fmt::Display for OnchainSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {}", e),
            Self::Decode(e) => write!(f, "decode error: {}", e),
            Self::NotVerified => write!(f, "contract not verified"),
            Self::NoSourceMap => write!(f, "no source map available"),
            Self::NoApiKey => write!(f, "ETHERSCAN_API_KEY not set"),
        }
    }
}

impl std::error::Error for OnchainSourceError {}

/// HTTP user agent we present to Sourcify/Etherscan.
const USER_AGENT: &str = concat!("recon-fuzzer/", env!("CARGO_PKG_VERSION"));

fn http_client() -> Result<reqwest::blocking::Client, OnchainSourceError> {
    reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| OnchainSourceError::Network(format!("client: {}", e)))
}

// ============================================================================
// Sourcify
// ============================================================================

#[derive(Debug, Deserialize)]
struct SourcifySource {
    content: String,
}

#[derive(Debug, Deserialize)]
struct SourcifyBytecodeMeta {
    #[serde(rename = "sourceMap")]
    source_map: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourcifyCompilation {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SourcifyResponse {
    sources: HashMap<String, SourcifySource>,
    #[serde(rename = "runtimeBytecode")]
    runtime_bytecode: Option<SourcifyBytecodeMeta>,
    compilation: SourcifyCompilation,
}

/// Fetch verified source from Sourcify. Mirrors
/// `Echidna.Onchain.Sourcify.fetchContractSource`.
pub fn fetch_sourcify(chain_id: u64, addr: Address) -> Result<OnchainSource, OnchainSourceError> {
    let url = format!(
        "https://sourcify.dev/server/v2/contract/{}/{}\
         ?fields=sources,creationBytecode.sourceMap,runtimeBytecode.sourceMap,\
runtimeBytecode.immutableReferences,compilation.name",
        chain_id,
        // Sourcify accepts checksummed or lowercase; checksummed is friendlier
        // to log lines.
        addr.to_checksum(None),
    );

    let client = http_client()?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| OnchainSourceError::Network(format!("sourcify GET: {}", e)))?;

    if !resp.status().is_success() {
        return Err(OnchainSourceError::NotVerified);
    }

    let body: SourcifyResponse = resp
        .json()
        .map_err(|e| OnchainSourceError::Decode(format!("sourcify json: {}", e)))?;

    let runtime_src_map = body
        .runtime_bytecode
        .and_then(|m| m.source_map)
        .ok_or(OnchainSourceError::NoSourceMap)?;

    let files = body
        .sources
        .into_iter()
        .map(|(path, src)| (path, src.content))
        .collect();

    Ok(OnchainSource {
        contract_name: body.compilation.name,
        files,
        runtime_src_map,
    })
}

// ============================================================================
// Etherscan v2 (fallback)
// ============================================================================

#[derive(Debug, Deserialize)]
struct EtherscanContent {
    content: String,
}

#[derive(Debug, Deserialize)]
struct EtherscanSourcesWrapper {
    sources: HashMap<String, EtherscanContent>,
}

#[derive(Debug, Deserialize)]
struct EtherscanResultEntry {
    #[serde(rename = "ContractName")]
    contract_name: String,
    #[serde(rename = "SourceCode")]
    source_code: String,
}

#[derive(Debug, Deserialize)]
struct EtherscanResponse {
    message: String,
    result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ChainlistEntry {
    chainid: String,
    blockexplorer: String,
    status: i64,
}

#[derive(Debug, Deserialize)]
struct ChainlistResponse {
    result: Vec<ChainlistEntry>,
}

/// Look up the block explorer URL for a chain id. Falls back to mainnet's
/// `https://etherscan.io` when the chain isn't in the list.
pub fn block_explorer_url(chain_id: u64) -> String {
    let client = match http_client() {
        Ok(c) => c,
        Err(_) => return "https://etherscan.io".to_string(),
    };
    let resp = match client
        .get("https://api.etherscan.io/v2/chainlist")
        .send()
        .and_then(|r| r.error_for_status())
    {
        Ok(r) => r,
        Err(_) => return "https://etherscan.io".to_string(),
    };
    let parsed: ChainlistResponse = match resp.json() {
        Ok(v) => v,
        Err(_) => return "https://etherscan.io".to_string(),
    };
    for entry in parsed.result {
        if entry.status == 1 && entry.chainid.parse::<u64>().ok() == Some(chain_id) {
            // Trim any trailing slash so `format!("{}/address/...", base)` works cleanly.
            return entry
                .blockexplorer
                .trim_end_matches('/')
                .to_string();
        }
    }
    "https://etherscan.io".to_string()
}

/// Echidna parses the `SourceCode` field in three formats. Mirrors
/// `Echidna.Onchain.Etherscan.parseSourceCode`.
fn parse_etherscan_source_code(
    contract_name: &str,
    code: &str,
) -> HashMap<String, String> {
    let try_json = |s: &str| -> Option<HashMap<String, String>> {
        if let Ok(wrapper) = serde_json::from_str::<EtherscanSourcesWrapper>(s) {
            return Some(
                wrapper
                    .sources
                    .into_iter()
                    .map(|(k, v)| (k, v.content))
                    .collect(),
            );
        }
        if let Ok(direct) = serde_json::from_str::<HashMap<String, EtherscanContent>>(s) {
            return Some(direct.into_iter().map(|(k, v)| (k, v.content)).collect());
        }
        None
    };

    // Format 1: {{...}} — strip outer braces and parse inner JSON.
    if let Some(rest) = code.strip_prefix('{') {
        if let Some(inner) = rest.strip_suffix('}') {
            if let Some(files) = try_json(inner) {
                return files;
            }
        }
    }

    // Format 2: {...} — try as nested or direct JSON.
    if let Some(files) = try_json(code) {
        return files;
    }

    // Format 3: plain Solidity source code, single file.
    let mut single = HashMap::new();
    single.insert(format!("{}.sol", contract_name), code.to_string());
    single
}

/// Fetch verified source from Etherscan v2 + scrape the source map from the
/// block explorer's HTML address page.
///
/// Retries the API call up to 5 times with the same `5s/n` decreasing backoff
/// echidna uses when the server returns a `NOTOK` (rate-limit-like) response.
pub fn fetch_etherscan(
    chain_id: u64,
    addr: Address,
    explorer_url: &str,
    api_key: &str,
) -> Result<OnchainSource, OnchainSourceError> {
    let url = format!(
        "https://api.etherscan.io/v2/api?\
chainid={}&module=contract&action=getsourcecode&address={}&apikey={}",
        chain_id,
        addr.to_checksum(None),
        api_key,
    );

    let client = http_client()?;
    let mut last_err = None;
    let mut entry: Option<EtherscanResultEntry> = None;
    for n in (1..=5).rev() {
        let send = client
            .get(&url)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<EtherscanResponse>());
        match send {
            Ok(resp) if resp.message.starts_with("OK") => {
                let entries: Vec<EtherscanResultEntry> = match serde_json::from_value(resp.result) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(OnchainSourceError::Decode(format!(
                            "etherscan result: {}",
                            e
                        )))
                    }
                };
                entry = entries.into_iter().next();
                break;
            }
            Ok(resp) => {
                tracing::debug!(
                    "Etherscan {}: NOTOK ({:?}), {} retries left",
                    addr,
                    resp.result,
                    n - 1
                );
                last_err = Some(OnchainSourceError::NotVerified);
            }
            Err(e) => {
                tracing::debug!("Etherscan {}: {}, {} retries left", addr, e, n - 1);
                last_err = Some(OnchainSourceError::Network(format!("etherscan GET: {}", e)));
            }
        }
        if n > 1 {
            // Echidna's backoff: 5_000_000us / n microseconds.
            std::thread::sleep(Duration::from_micros(5_000_000 / n as u64));
        }
    }
    let entry = entry.ok_or_else(|| last_err.unwrap_or(OnchainSourceError::NotVerified))?;

    if entry.source_code.trim().is_empty() {
        return Err(OnchainSourceError::NotVerified);
    }

    let files = parse_etherscan_source_code(&entry.contract_name, &entry.source_code);

    // Source map: Etherscan's API doesn't expose it, so HTML-scrape the
    // explorer page (matches `Echidna.Onchain.Etherscan.fetchContractSourceMap`).
    let runtime_src_map = fetch_etherscan_source_map(explorer_url, addr).ok_or(
        OnchainSourceError::NoSourceMap,
    )?;

    Ok(OnchainSource {
        contract_name: entry.contract_name,
        files,
        runtime_src_map,
    })
}

/// HTML-scrape the source map from a block explorer's address page.
///
/// The explorer renders the runtime source map inside one of the
/// `<pre>` blocks beneath `id="dividcode"`. There may be several such
/// `<pre>` blocks, so we walk them in reverse (matching echidna) and
/// pick the *last* one that parses as a valid source map.
pub fn fetch_etherscan_source_map(explorer_url: &str, addr: Address) -> Option<String> {
    use scraper::{Html, Selector};

    let url = format!("{}/address/{}", explorer_url, addr.to_checksum(None));
    let client = http_client().ok()?;
    let html = client
        .get(&url)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .ok()?;

    let doc = Html::parse_document(&html);
    let pre_sel = Selector::parse("#dividcode pre").ok()?;
    let candidates: Vec<String> = doc
        .select(&pre_sel)
        .map(|n| n.text().collect::<String>())
        .collect();

    // Walk newest → oldest like echidna.
    for candidate in candidates.into_iter().rev() {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        // The source map is a sequence of `s:l:f:j:m` entries separated by
        // `;`. We accept any string whose first non-empty entry parses to a
        // numeric file index — this is the same liberal approach hevm's
        // `makeSrcMaps` takes.
        if looks_like_source_map(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn looks_like_source_map(s: &str) -> bool {
    // First non-empty entry should parse: at minimum a leading numeric
    // (start offset) followed by `:` is a strong signal.
    for entry in s.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(':');
        let first = parts.next().unwrap_or("");
        return !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

// ============================================================================
// High-level fetch orchestration
// ============================================================================

/// Try Sourcify first, then Etherscan if `ETHERSCAN_API_KEY` is in the env.
/// Returns `None` if no verified source is available.
pub fn fetch_onchain_source(
    chain_id: u64,
    addr: Address,
    explorer_url: &str,
) -> Option<OnchainSource> {
    match fetch_sourcify(chain_id, addr) {
        Ok(s) => return Some(s),
        Err(e) => tracing::debug!("Sourcify miss for {:?}: {}", addr, e),
    }

    let api_key = match std::env::var("ETHERSCAN_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            tracing::debug!(
                "No ETHERSCAN_API_KEY set, skipping Etherscan fallback for {:?}",
                addr
            );
            return None;
        }
    };

    match fetch_etherscan(chain_id, addr, explorer_url, &api_key) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::debug!("Etherscan miss for {:?}: {}", addr, e);
            None
        }
    }
}

// ============================================================================
// Coverage rendering for one external contract
// ============================================================================

/// Render `<dir>/covered.<unix>.html` and `.lcov` for a single external
/// contract whose runtime bytecode is `bytecode` and whose verified source
/// data is `source`. Returns `(html_path, lcov_path)` on success.
///
/// Works by building a one-entry `codehash → ContractSourceInfo` map and
/// reusing the existing `SourceCoverage` rendering pipeline so on-chain
/// reports look identical to the local Recon coverage report.
pub fn render_onchain_coverage(
    coverage_map: &super::inspector::CoverageMap,
    addr: Address,
    bytecode: &Bytes,
    source: &OnchainSource,
    out_dir: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let _ = addr;
    // Build the source-file map keyed by *file id* (the integer that appears
    // in the Solidity source-map's third field). We assign ids in the same
    // order Solidity emits sources by default — first key in the
    // `sources` map is id 0, etc. This matches what `solc` does when the
    // contract is compiled standalone.
    let mut path_to_id: HashMap<String, i32> = HashMap::new();
    let mut source_files: HashMap<i32, SourceFile> = HashMap::new();
    let mut sorted_paths: Vec<&String> = source.files.keys().collect();
    sorted_paths.sort();
    for (i, path) in sorted_paths.iter().enumerate() {
        let id = i as i32;
        path_to_id.insert((*path).clone(), id);
        let pb = PathBuf::from(path);
        let content = source.files.get(*path).cloned().unwrap_or_default();
        source_files.insert(id, SourceFile::new(pb, content));
    }

    let codehash: B256 = keccak256(bytecode);
    let info = ContractSourceInfo {
        name: source.contract_name.clone(),
        deployed_bytecode: bytecode.to_vec(),
        source_map: SourceMap {
            locations: parse_source_map(&source.runtime_src_map),
        },
        // file_id is unused for resolution (locations carry their own
        // file_id), but we set it to the first valid one for parity with
        // `build_codehash_to_source_info`.
        file_id: 0,
    };

    let mut codehash_map = HashMap::new();
    codehash_map.insert(codehash, info);

    // Reduce the global coverage map to just this address's codehash to
    // avoid leaking other contracts' hits into the per-address report.
    let mut filtered: super::inspector::CoverageMap = Default::default();
    if let Some(entries) = coverage_map.get(&codehash) {
        filtered.insert(codehash, entries.clone());
    }

    // If the bytecode we have doesn't match anything in the coverage map,
    // emit an empty (all-zero-hits) report rather than failing — it's still
    // useful to know the source rendered cleanly even if no PCs were hit.
    let mut coverage =
        super::source::generate_source_coverage_multi(&filtered, &codehash_map, &source_files);

    // Mark the contract's directory deterministic: drop coverage for files
    // not in this contract's source set so we don't accidentally render
    // unrelated files (the multi function adds entries for every file in
    // every contract by default — fine here since codehash_map has one
    // contract, but be defensive).
    let allowed_paths: std::collections::HashSet<PathBuf> = source_files
        .values()
        .map(|sf| sf.path.clone())
        .collect();
    coverage.files.retain(|p, _| allowed_paths.contains(p));

    // Project root for relative paths in the report = the per-address
    // directory itself, so the explorer-style file paths from Sourcify (e.g.
    // `contracts/StableSwap.vy`) display verbatim.
    std::fs::create_dir_all(out_dir)?;
    let project_root = out_dir;

    let lcov_path = save_lcov_report(&coverage, project_root, out_dir)?;
    let html_path = save_html_report(&coverage, project_root, out_dir, &source_files)?;

    Ok((html_path, lcov_path))
}

/// Echidna-style runId: unix seconds, used in `covered.<runId>.{html,lcov}`.
pub fn run_id_from_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One on-chain contract that produced a coverage report.
#[derive(Debug, Clone)]
pub struct RenderedOnchainReport {
    pub address: Address,
    pub contract_name: String,
    pub html_path: PathBuf,
    pub lcov_path: PathBuf,
}

/// End-of-campaign hook: for every contract whose code the fork pulled from
/// RPC during this run, fetch verified source (Sourcify → Etherscan) and
/// render `<corpus>/<addr>/covered.<runId>.{html,lcov}`.
///
/// Mirrors `Echidna.Onchain.saveCoverageReport` closely:
/// - addresses use EIP-55 checksum casing in the directory name
/// - explorer URL is resolved up-front from the chainlist API
/// - addresses with no verified source are silently skipped
///
/// Returns the list of reports that were successfully rendered.
pub fn save_onchain_coverage_reports(
    chain_id: u64,
    contracts: &[(Address, Bytes)],
    coverage_map: &super::inspector::CoverageMap,
    corpus_dir: &Path,
) -> Vec<RenderedOnchainReport> {
    if contracts.is_empty() {
        return Vec::new();
    }

    // Resolve block explorer URL once. (Only used by the Etherscan fallback,
    // but echidna fetches it unconditionally so we do the same.)
    let explorer_url = block_explorer_url(chain_id);
    let run_id = run_id_from_now();

    let mut reports = Vec::new();
    for (addr, bytecode) in contracts {
        match fetch_onchain_source(chain_id, *addr, &explorer_url) {
            Some(source) => {
                let dir = corpus_dir.join(addr.to_checksum(None));
                match render_onchain_coverage_with_run_id(
                    coverage_map,
                    *addr,
                    bytecode,
                    &source,
                    &dir,
                    run_id,
                ) {
                    Ok((html_path, lcov_path)) => {
                        tracing::info!(
                            "Saved on-chain coverage for {} ({}): {:?}",
                            addr.to_checksum(None),
                            source.contract_name,
                            html_path
                        );
                        reports.push(RenderedOnchainReport {
                            address: *addr,
                            contract_name: source.contract_name,
                            html_path,
                            lcov_path,
                        });
                    }
                    Err(e) => tracing::warn!(
                        "Failed to render on-chain coverage for {}: {}",
                        addr.to_checksum(None),
                        e
                    ),
                }
            }
            None => tracing::debug!(
                "No verified source found for {}, skipping on-chain coverage",
                addr.to_checksum(None)
            ),
        }
    }
    reports
}

/// Same as [`render_onchain_coverage`] but lets the caller supply the runId
/// so a single campaign emits the same `covered.<runId>` suffix on every
/// per-address directory (matching echidna).
pub fn render_onchain_coverage_with_run_id(
    coverage_map: &super::inspector::CoverageMap,
    addr: Address,
    bytecode: &Bytes,
    source: &OnchainSource,
    out_dir: &Path,
    run_id: u64,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let _ = addr;
    let mut path_to_id: HashMap<String, i32> = HashMap::new();
    let mut source_files: HashMap<i32, SourceFile> = HashMap::new();
    let mut sorted_paths: Vec<&String> = source.files.keys().collect();
    sorted_paths.sort();
    for (i, path) in sorted_paths.iter().enumerate() {
        let id = i as i32;
        path_to_id.insert((*path).clone(), id);
        let pb = PathBuf::from(path);
        let content = source.files.get(*path).cloned().unwrap_or_default();
        source_files.insert(id, SourceFile::new(pb, content));
    }

    // Two codehash keys to look up runtime PC hits under, mirroring the
    // inspector's resolve flow:
    //   1. The real `keccak256(bytecode)` (used when an external contract
    //      happens to share the metadata hash of a local compile target).
    //   2. The length-pseudo-hash `B256` with `bytecode.len()` packed into
    //      bytes 24..32 — the inspector's final fallback for unknown
    //      contracts, which fork-loaded bytecodes always hit.
    let real_codehash: B256 = keccak256(bytecode);
    let mut len_bytes = [0u8; 32];
    len_bytes[24..32].copy_from_slice(&(bytecode.len() as u64).to_be_bytes());
    let len_codehash: B256 = B256::from(len_bytes);

    let info = ContractSourceInfo {
        name: source.contract_name.clone(),
        deployed_bytecode: bytecode.to_vec(),
        source_map: SourceMap {
            locations: parse_source_map(&source.runtime_src_map),
        },
        file_id: 0,
    };

    let mut codehash_map = HashMap::new();
    codehash_map.insert(real_codehash, info.clone());
    codehash_map.insert(len_codehash, info);

    let mut filtered: super::inspector::CoverageMap = Default::default();
    for key in [real_codehash, len_codehash] {
        if let Some(entries) = coverage_map.get(&key) {
            filtered.insert(key, entries.clone());
        }
    }

    let mut coverage =
        super::source::generate_source_coverage_multi(&filtered, &codehash_map, &source_files);

    let allowed_paths: std::collections::HashSet<PathBuf> = source_files
        .values()
        .map(|sf| sf.path.clone())
        .collect();
    coverage.files.retain(|p, _| allowed_paths.contains(p));

    std::fs::create_dir_all(out_dir)?;
    let project_root = out_dir;

    // Use the supplied runId for filenames so all per-address reports from
    // one campaign share the same suffix.
    let lcov_path = out_dir.join(format!("covered.{}.lcov", run_id));
    let html_path = out_dir.join(format!("covered.{}.html", run_id));
    std::fs::write(&lcov_path, coverage.to_lcov(project_root))?;
    let mut id_to_path: HashMap<PathBuf, i32> = HashMap::new();
    for (id, sf) in &source_files {
        id_to_path.insert(sf.path.clone(), *id);
    }
    std::fs::write(
        &html_path,
        coverage.to_html(project_root, &source_files, &id_to_path),
    )?;

    Ok((html_path, lcov_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_source_code_plain() {
        let files = parse_etherscan_source_code("Foo", "contract Foo {}");
        assert_eq!(files.len(), 1);
        assert!(files.contains_key("Foo.sol"));
    }

    #[test]
    fn parse_source_code_double_braces() {
        let body = r#"{{"sources": {"a.sol": {"content": "contract A {}"}}}}"#;
        let files = parse_etherscan_source_code("A", body);
        assert_eq!(files.get("a.sol").unwrap(), "contract A {}");
    }

    #[test]
    fn parse_source_code_direct() {
        let body = r#"{"a.sol": {"content": "contract A {}"}, "b.sol": {"content": "x"}}"#;
        let files = parse_etherscan_source_code("A", body);
        assert_eq!(files.len(), 2);
        assert_eq!(files.get("b.sol").unwrap(), "x");
    }

    #[test]
    fn parse_source_code_nested() {
        let body = r#"{"sources": {"a.sol": {"content": "contract A {}"}}}"#;
        let files = parse_etherscan_source_code("A", body);
        assert_eq!(files.get("a.sol").unwrap(), "contract A {}");
    }

    #[test]
    fn detect_source_map_string() {
        assert!(looks_like_source_map("65:541:12:-:0;;;88:21"));
        assert!(!looks_like_source_map("hello world"));
        assert!(!looks_like_source_map(""));
    }
}

// keep imports referenced even when only used internally
#[allow(dead_code)]
fn _ensure_used(_: FileCoverage, _: SourceCoverage) {}

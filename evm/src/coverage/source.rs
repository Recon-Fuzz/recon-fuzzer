//! Source-level coverage reporting
//!
//! Maps PC-level coverage to source code lines and generates LCOV reports

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use super::inspector::CoverageMap;

/// Source location from source map
#[derive(Debug, Clone, Default)]
pub struct SrcLocation {
    /// Start byte offset in source file
    pub start: u32,
    /// Length in bytes
    pub length: u32,
    /// File index (from source list)
    pub file_id: i32,
    /// Jump type: 'i' = into, 'o' = out, '-' = regular
    pub jump: char,
    /// Modifier depth
    pub modifier_depth: u32,
}

/// Parsed source map for a contract
#[derive(Debug, Clone)]
pub struct SourceMap {
    /// List of source locations, indexed by instruction index (not PC!)
    pub locations: Vec<SrcLocation>,
}

/// Contract info needed for coverage mapping
#[derive(Debug, Clone)]
pub struct ContractSourceInfo {
    /// Contract name
    pub name: String,
    /// Deployed bytecode (for PC to instruction index mapping)
    pub deployed_bytecode: Vec<u8>,
    /// Parsed source map
    pub source_map: SourceMap,
    /// File ID from AST (for matching)
    pub file_id: i32,
}

/// Source file info
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute path to file
    pub path: PathBuf,
    /// File content
    pub content: String,
    /// Line start offsets (for offset -> line conversion)
    pub line_offsets: Vec<usize>,
}

impl SourceFile {
    /// Create from file path and content
    pub fn new(path: PathBuf, content: String) -> Self {
        let line_offsets = std::iter::once(0)
            .chain(content.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        Self {
            path,
            content,
            line_offsets,
        }
    }

    /// Convert byte offset to line number (1-based)
    pub fn offset_to_line(&self, offset: usize) -> usize {
        match self.line_offsets.binary_search(&offset) {
            Ok(line) => line + 1,
            Err(line) => line, // line is where it would be inserted, which is the current line
        }
    }
}

/// Coverage info for a single source file
#[derive(Debug, Clone, Default)]
pub struct FileCoverage {
    /// Line number -> hit count
    pub line_hits: BTreeMap<usize, usize>,
}

/// Complete source coverage data
#[derive(Debug, Clone)]
pub struct SourceCoverage {
    /// File path -> coverage
    pub files: HashMap<PathBuf, FileCoverage>,
}

impl SourceCoverage {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Generate LCOV format output
    pub fn to_lcov(&self, project_root: &Path) -> String {
        let mut output = String::from("TN:\n");

        // Sort files for consistent output
        let mut files: Vec<_> = self.files.iter().collect();
        files.sort_by_key(|(path, _)| *path);

        for (path, coverage) in files {
            // Make path absolute if needed, and canonicalize
            let abs_path = if path.is_absolute() {
                path.clone()
            } else {
                project_root.join(path)
            };

            // Canonicalize to clean up /./ and /../
            let clean_path = abs_path.canonicalize().unwrap_or(abs_path);

            output.push_str(&format!("SF:{}\n", clean_path.display()));

            // Output DA (data) lines sorted by line number
            for (line, hits) in &coverage.line_hits {
                output.push_str(&format!("DA:{},{}\n", line, hits));
            }

            output.push_str("end_of_record\n\n");
        }

        output
    }

    pub fn to_html(&self, project_root: &Path, source_files: &HashMap<i32, SourceFile>, file_id_to_path: &HashMap<PathBuf, i32>) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Calculate statistics
        let mut total_lines = 0usize;
        let mut total_covered = 0usize;
        let mut total_coverable = 0usize;

        // Build file data
        let mut file_entries: Vec<HtmlFileEntry> = Vec::new();

        // Sort files for consistent output
        let mut files: Vec<_> = self.files.iter().collect();
        files.sort_by_key(|(path, _)| *path);

        for (path, coverage) in files {
            // Find the source file content
            let file_id = file_id_to_path.get(path).copied();
            let source_content = file_id.and_then(|id| source_files.get(&id));

            let source_lines: Vec<&str> = source_content
                .map(|sf| sf.content.lines().collect())
                .unwrap_or_default();

            let file_total_lines = source_lines.len();
            let coverable_lines = coverage.line_hits.len();
            let covered_lines = coverage.line_hits.values().filter(|&&h| h > 0).count();

            total_lines += file_total_lines;
            total_coverable += coverable_lines;
            total_covered += covered_lines;

            let coverage_pct = if coverable_lines > 0 {
                (covered_lines * 100) / coverable_lines
            } else {
                0
            };

            // Make path relative for display
            let display_path = path
                .strip_prefix(project_root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            // Generate file ID for HTML anchors
            let file_id_str: String = display_path
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect();

            // Build line entries
            let mut line_entries: Vec<HtmlLineEntry> = Vec::new();
            for (line_num, line_content) in source_lines.iter().enumerate() {
                let line_1based = line_num + 1;
                let hits = coverage.line_hits.get(&line_1based).copied();
                let row_class = match hits {
                    Some(h) if h > 0 => Some("row-line-covered"),
                    Some(_) => Some("row-line-uncovered"),
                    None => None, // Not a coverable line
                };
                line_entries.push(HtmlLineEntry {
                    line_number: line_1based,
                    source_code: html_escape(line_content),
                    row_class: row_class.map(|s| s.to_string()),
                    hit_count: hits, // Show hit count for coverable lines
                });
            }

            file_entries.push(HtmlFileEntry {
                file_id: file_id_str,
                file_path: display_path,
                active_lines: coverable_lines,
                covered_lines,
                coverage_percentage: coverage_pct,
                coverage_color: get_coverage_color_hsl(coverage_pct),
                coverage_color_alpha: get_coverage_color_alpha(coverage_pct),
                lines: line_entries,
            });
        }

        let total_coverage_pct = if total_coverable > 0 {
            (total_covered * 100) / total_coverable
        } else {
            0
        };

        // Get timestamp as Unix epoch (simpler, no external crate needed)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| {
                let secs = d.as_secs();
                // Format as ISO-ish date using basic math
                let days_since_epoch = secs / 86400;
                let time_of_day = secs % 86400;
                let hours = time_of_day / 3600;
                let minutes = (time_of_day % 3600) / 60;
                let seconds = time_of_day % 60;
                // Approximate date calculation (good enough for display)
                let (year, month, day) = days_to_ymd(days_since_epoch);
                format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", year, month, day, hours, minutes, seconds)
            })
            .unwrap_or_else(|_| "Unknown".to_string());

        // Generate HTML
        generate_html_report(
            "Recon Coverage Report",
            file_entries.len(),
            total_lines,
            total_covered,
            total_coverable,
            total_coverage_pct,
            &timestamp,
            file_entries,
        )
    }
}

impl Default for SourceCoverage {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceCoverage {
    /// Filter coverage to only include relevant source files
    ///
    /// Simple and accurate filtering:
    /// 1. ALL files in src/ are included (always show project sources)
    /// 2. Files that have at least 1 hit are included (actually executed code)
    ///
    /// This filters out external library files that were never executed.
    pub fn filter_relevant_sources(&mut self, project_path: &Path) {
        // Keep only files that are relevant
        self.files.retain(|file_path, file_cov| {
            // Get the relative path for comparison
            let relative_path = file_path
                .strip_prefix(project_path)
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|_| file_path.clone());

            let relative_str = relative_path.to_string_lossy();
            let normalized_str = relative_str.replace('\\', "/");

            // Rule 1: ALL src/ files are included
            if normalized_str.starts_with("src/") || relative_path.starts_with("src") {
                return true;
            }

            // Rule 2: Files with at least 1 hit are included (actually executed)
            let has_hits = file_cov.line_hits.values().any(|&hits| hits > 0);
            if has_hits {
                return true;
            }

            // Everything else filtered out
            tracing::debug!(
                "Filtering out coverage for: {} (not in src/ and no hits)",
                file_path.display()
            );
            false
        });
    }
}

/// Parse a source map string into SrcLocation entries
/// Format: "s:l:f:j:m" separated by ";"
/// Values carry forward if empty
pub fn parse_source_map(source_map: &str) -> Vec<SrcLocation> {
    let mut locations = Vec::new();
    let mut prev = SrcLocation::default();

    for entry in source_map.split(';') {
        let parts: Vec<&str> = entry.split(':').collect();
        let mut loc = prev.clone();

        // Parse each component, keeping previous value if empty
        if let Some(s) = parts.first().filter(|s| !s.is_empty()) {
            if let Ok(v) = s.parse::<i32>() {
                loc.start = v as u32;
            }
        }
        if let Some(l) = parts.get(1).filter(|s| !s.is_empty()) {
            if let Ok(v) = l.parse::<u32>() {
                loc.length = v;
            }
        }
        if let Some(f) = parts.get(2).filter(|s| !s.is_empty()) {
            if let Ok(v) = f.parse::<i32>() {
                loc.file_id = v;
            }
        }
        if let Some(j) = parts.get(3).filter(|s| !s.is_empty()) {
            loc.jump = j.chars().next().unwrap_or('-');
        }
        if let Some(m) = parts.get(4).filter(|s| !s.is_empty()) {
            if let Ok(v) = m.parse::<u32>() {
                loc.modifier_depth = v;
            }
        }

        prev = loc.clone();
        locations.push(loc);
    }

    locations
}

/// Build a PC -> instruction index mapping from bytecode
/// This handles variable-length instructions (PUSH1-PUSH32)
pub fn build_pc_to_index(bytecode: &[u8]) -> HashMap<usize, usize> {
    let mut pc_to_idx = HashMap::new();
    let mut pc = 0usize;
    let mut idx = 0usize;

    while pc < bytecode.len() {
        pc_to_idx.insert(pc, idx);

        let opcode = bytecode[pc];
        // PUSH1 (0x60) to PUSH32 (0x7f) have immediate data
        let push_size = if (0x60..=0x7f).contains(&opcode) {
            (opcode - 0x5f) as usize
        } else {
            0
        };

        pc += 1 + push_size;
        idx += 1;
    }

    pc_to_idx
}

/// Build a map from codehash to ContractSourceInfo for all contracts (deployed bytecode)
/// This enables coverage mapping for externally-called contracts (like LibraryUser).
///
/// `index` is used to remap each contract's source-map file ids from its
/// build-info-local space into the global space used by `index.source_files`.
pub fn build_codehash_to_source_info(
    contracts: &[crate::foundry::CompiledContract],
    index: &SourceInfoIndex,
) -> HashMap<alloy_primitives::B256, ContractSourceInfo> {
    use alloy_primitives::keccak256;

    let mut map = HashMap::new();

    for contract in contracts {
        if contract.deployed_bytecode.is_empty() {
            continue;
        }

        // Skip contracts without source maps
        let source_map_str = match &contract.source_map {
            Some(sm) if !sm.is_empty() => sm,
            _ => continue,
        };

        // Compute the compile-time codehash
        let codehash = keccak256(&contract.deployed_bytecode);

        // Resolve this contract's build-info and remap its source-map file ids
        // into the global id space.
        let remap = index.remap_for_contract(&contract.source_path, contract.source_file_id);
        if remap.is_none() {
            tracing::warn!(
                "no build-info match for contract {} (source_path={}, source_file_id={:?}); \
                 coverage for this contract will be misattributed — \
                 try `forge clean && forge build --build-info`",
                contract.name,
                contract.source_path.display(),
                contract.source_file_id
            );
        }
        let mut locations = parse_source_map(source_map_str);
        for loc in &mut locations {
            loc.file_id = SourceInfoIndex::apply_remap(remap, loc.file_id);
        }
        let source_map = SourceMap { locations };

        // Get file ID from first valid source map entry
        let file_id = source_map.locations.iter()
            .find(|loc| loc.file_id >= 0)
            .map(|loc| loc.file_id)
            .unwrap_or(-1);

        let info = ContractSourceInfo {
            name: contract.name.clone(),
            deployed_bytecode: contract.deployed_bytecode.to_vec(),
            source_map,
            file_id,
        };

        tracing::debug!(
            "SourceInfo (runtime): {} -> codehash={:?} file_id={} srcmap_entries={}",
            contract.name,
            codehash,
            file_id,
            info.source_map.locations.len()
        );

        map.insert(codehash, info.clone());

        // ALSO add a length-based pseudo-hash entry as fallback
        // This matches the fallback logic in CombinedInspector when metadata lookup fails
        // (e.g., for contracts with immutables where runtime bytecode differs from compile-time)
        let bytecode_len = contract.deployed_bytecode.len();
        let mut len_bytes = [0u8; 32];
        len_bytes[24..32].copy_from_slice(&(bytecode_len as u64).to_be_bytes());
        let len_codehash = alloy_primitives::B256::from(len_bytes);

        // Only add if not already present (avoid overwriting real codehash entries)
        if !map.contains_key(&len_codehash) {
            tracing::debug!(
                "SourceInfo (length fallback): {} -> len_codehash={:?} (bytecode_len={})",
                contract.name,
                len_codehash,
                bytecode_len
            );
            map.insert(len_codehash, info);
        }
    }
    map
}

/// Build a map from codehash to ContractSourceInfo for init/constructor code.
/// This enables coverage mapping for constructor execution.
///
/// `index` is used to remap each contract's source-map file ids from its
/// build-info-local space into the global space used by `index.source_files`.
pub fn build_init_codehash_to_source_info(
    contracts: &[crate::foundry::CompiledContract],
    index: &SourceInfoIndex,
) -> HashMap<alloy_primitives::B256, ContractSourceInfo> {
    use alloy_primitives::keccak256;

    let mut map = HashMap::new();

    for contract in contracts {
        if contract.bytecode.is_empty() {
            continue;
        }

        // Skip contracts without init source maps
        let source_map_str = match &contract.init_source_map {
            Some(sm) if !sm.is_empty() => sm,
            _ => continue,
        };

        // Compute the codehash of init bytecode
        let codehash = keccak256(&contract.bytecode);

        // Resolve this contract's build-info and remap its source-map file ids
        // into the global id space.
        let remap = index.remap_for_contract(&contract.source_path, contract.source_file_id);
        let mut locations = parse_source_map(source_map_str);
        for loc in &mut locations {
            loc.file_id = SourceInfoIndex::apply_remap(remap, loc.file_id);
        }
        let source_map = SourceMap { locations };

        // Get file ID from first valid source map entry
        let file_id = source_map.locations.iter()
            .find(|loc| loc.file_id >= 0)
            .map(|loc| loc.file_id)
            .unwrap_or(-1);

        let info = ContractSourceInfo {
            name: format!("{} (constructor)", contract.name),
            deployed_bytecode: contract.bytecode.to_vec(), // Using init bytecode here
            source_map,
            file_id,
        };

        tracing::debug!(
            "SourceInfo (init): {} -> codehash={:?} file_id={} srcmap_entries={}",
            contract.name,
            codehash,
            file_id,
            info.source_map.locations.len()
        );

        map.insert(codehash, info.clone());

        // ALSO add a length-based pseudo-hash entry as fallback (same as runtime)
        let bytecode_len = contract.bytecode.len();
        let mut len_bytes = [0u8; 32];
        len_bytes[24..32].copy_from_slice(&(bytecode_len as u64).to_be_bytes());
        let len_codehash = alloy_primitives::B256::from(len_bytes);

        if !map.contains_key(&len_codehash) {
            tracing::debug!(
                "SourceInfo (init length fallback): {} -> len_codehash={:?} (bytecode_len={})",
                contract.name,
                len_codehash,
                bytecode_len
            );
            map.insert(len_codehash, info);
        }
    }
    map
}

/// Type alias for the codehash to source info map
pub type CodehashToSourceInfo = HashMap<alloy_primitives::B256, ContractSourceInfo>;

/// Foundry artifact structures for parsing
#[derive(Debug, Deserialize)]
struct FoundryArtifactFull {
    #[serde(rename = "deployedBytecode")]
    deployed_bytecode: DeployedBytecode,
    /// Top-level `id` — file id of this artifact's source within its build-info.
    #[serde(default)]
    id: Option<i32>,
    /// Foundry metadata; we read `settings.compilationTarget` to learn the
    /// artifact's source path independently of the artifact filename.
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DeployedBytecode {
    object: String,
    #[serde(rename = "sourceMap", default)]
    source_map: Option<String>,
}

/// Build-info JSON parsed to extract per-build-info file-id → path mappings.
/// Supports both the legacy schema (`output.sources[path].id`) and the newer
/// compact schema (top-level `source_id_to_path`).
#[derive(Debug, Deserialize)]
struct BuildInfoRaw {
    /// Newer compact format: { "0": "lib/forge-std/src/Base.sol", ... }
    #[serde(default)]
    source_id_to_path: HashMap<String, String>,
    /// Older format: { "output": { "sources": { "path": { "id": N }, ... } } }
    #[serde(default)]
    output: Option<BuildOutput>,
}

#[derive(Debug, Default, Deserialize)]
struct BuildOutput {
    #[serde(default)]
    sources: HashMap<String, SourceInfo>,
}

#[derive(Debug, Deserialize)]
struct SourceInfo {
    id: i32,
}

impl BuildInfoRaw {
    /// Return this build-info's local file id → source path mapping, merging
    /// both schema forms. The newer compact form takes precedence when both
    /// are present.
    fn local_id_to_path(&self) -> HashMap<i32, PathBuf> {
        let mut out: HashMap<i32, PathBuf> = HashMap::new();
        if !self.source_id_to_path.is_empty() {
            for (k, v) in &self.source_id_to_path {
                if let Ok(id) = k.parse::<i32>() {
                    out.insert(id, PathBuf::from(v));
                }
            }
            return out;
        }
        if let Some(output) = &self.output {
            for (path, info) in &output.sources {
                out.insert(info.id, PathBuf::from(path));
            }
        }
        out
    }
}

/// Index built from all `out/build-info/*.json` files.
///
/// Foundry can leave multiple build-info JSONs in `out/build-info/` (incremental
/// builds, multiple compile profiles, different solc versions). Each build-info
/// has its OWN file-id space — the same numeric id can refer to different
/// source paths across build-infos. The naive "merge into one map" loses data
/// silently and produces wrong coverage reports.
///
/// This index keeps each build-info's file-id space separate, assigns global
/// ids on top, and lets callers ask "which build-info produced this artifact?"
/// so source-map file ids can be remapped through the right one.
#[derive(Debug, Default, Clone)]
pub struct SourceInfoIndex {
    /// Source files keyed by GLOBAL file id (one id per unique source path).
    pub source_files: HashMap<i32, SourceFile>,
    /// Path → global file id (inverse of source_files keys).
    path_to_global: HashMap<PathBuf, i32>,
    /// Per-build-info remap: build_info_hash → (local_id → global_id).
    build_info_remaps: HashMap<String, HashMap<i32, i32>>,
    /// (source_path, local_file_id) → build_info_hash.
    /// Lets us identify which build-info compiled an artifact via its top-level
    /// `id` field combined with its source path.
    contract_to_build_info: HashMap<(PathBuf, i32), String>,
    /// source_path → list of build_info_hashes that contain this source.
    /// Fallback when a contract artifact has no `id` field — we pick any
    /// build-info that contains its source path.
    path_to_build_infos: HashMap<PathBuf, Vec<String>>,
}

impl SourceInfoIndex {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Look up the local→global remap for the build-info that compiled this
    /// contract. The key is `(contract.source_path, contract.source_file_id)`;
    /// when `source_file_id` is None we fall back to any build-info that
    /// contains the source path.
    pub fn remap_for_contract(
        &self,
        source_path: &Path,
        local_file_id: Option<i32>,
    ) -> Option<&HashMap<i32, i32>> {
        if let Some(fid) = local_file_id {
            let key = (source_path.to_path_buf(), fid);
            if let Some(hash) = self.contract_to_build_info.get(&key) {
                return self.build_info_remaps.get(hash);
            }
        }
        // Fallback: pick the first build-info that contains this source path.
        let hashes = self.path_to_build_infos.get(source_path)?;
        let hash = hashes.first()?;
        self.build_info_remaps.get(hash)
    }

    /// Apply a (possibly absent) remap to a single source-map file id.
    /// Negative ids (sentinel for "no source") pass through; ids that the
    /// remap can't translate become -1 so downstream code skips them.
    pub fn apply_remap(remap: Option<&HashMap<i32, i32>>, local_id: i32) -> i32 {
        if local_id < 0 {
            return local_id;
        }
        match remap {
            Some(m) => m.get(&local_id).copied().unwrap_or(-1),
            None => local_id, // No remap available — keep id as-is (legacy behaviour).
        }
    }
}

/// Time window (seconds) used to discard stale build-info files. Foundry can
/// leave old build-info JSONs in `out/build-info/` from previous compiles
/// (different solc versions, scrapped profiles). We treat the most recent
/// build-info's mtime as the reference and ignore anything older than this
/// window — those stale files would otherwise contribute file ids that no
/// current artifact references, polluting the global remap.
const BUILD_INFO_FRESH_WINDOW_SECS: u64 = 30;

/// Load source coverage data from a Foundry project.
///
/// Reads every recent `out/build-info/*.json` independently, assigns
/// globally-unique file ids by source path, and records a per-build-info
/// `local_id → global_id` remap. Source maps in contract artifacts use ids
/// local to their build-info, so callers must remap them via
/// [`SourceInfoIndex::remap_for_contract`] before indexing into `source_files`.
///
/// Build-info files are filtered to those whose mtime is within
/// [`BUILD_INFO_FRESH_WINDOW_SECS`] of the newest one — this drops stale
/// build-info JSONs from older compiles that no current artifact references.
pub fn load_source_info(project_path: &Path) -> Result<SourceInfoIndex> {
    let out_dir = project_path.join("out");
    let build_info_dir = out_dir.join("build-info");

    let mut index = SourceInfoIndex::empty();

    if !build_info_dir.exists() {
        return Ok(index);
    }

    let mut next_global: i32 = 0;

    // Collect (path, mtime) for every build-info JSON.
    let mut paths_with_mtime: Vec<(PathBuf, std::time::SystemTime)> = fs::read_dir(&build_info_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "json"))
        .filter_map(|p| {
            let mtime = fs::metadata(&p).and_then(|m| m.modified()).ok()?;
            Some((p, mtime))
        })
        .collect();

    // Drop stale build-info files: keep only those within
    // BUILD_INFO_FRESH_WINDOW_SECS of the newest mtime.
    if let Some(newest) = paths_with_mtime.iter().map(|(_, t)| *t).max() {
        let window = std::time::Duration::from_secs(BUILD_INFO_FRESH_WINDOW_SECS);
        let total_before = paths_with_mtime.len();
        paths_with_mtime.retain(|(_, t)| match newest.duration_since(*t) {
            Ok(age) => age <= window,
            // mtime is in the future relative to "newest" — keep it.
            Err(_) => true,
        });
        let dropped = total_before - paths_with_mtime.len();
        if dropped > 0 {
            tracing::debug!(
                "load_source_info: dropping {} stale build-info file(s) (older than {}s from newest)",
                dropped,
                BUILD_INFO_FRESH_WINDOW_SECS
            );
        }
    }

    // Iterate fresh build-info files in sorted order so global-id assignment
    // is stable across runs.
    let mut entries: Vec<PathBuf> = paths_with_mtime.into_iter().map(|(p, _)| p).collect();
    entries.sort();

    for path in entries {
        let bi_hash = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let bi: BuildInfoRaw = match serde_json::from_str(&content) {
            Ok(bi) => bi,
            Err(e) => {
                tracing::debug!("Skipping build-info {}: {}", path.display(), e);
                continue;
            }
        };

        let local_to_path = bi.local_id_to_path();
        if local_to_path.is_empty() {
            continue;
        }

        let mut remap: HashMap<i32, i32> = HashMap::with_capacity(local_to_path.len());

        for (local_id, src_path) in &local_to_path {
            // Assign or reuse a global id for this source path.
            let global_id = match index.path_to_global.get(src_path) {
                Some(&g) => g,
                None => {
                    let g = next_global;
                    next_global += 1;
                    index.path_to_global.insert(src_path.clone(), g);
                    // Eagerly load the source file content.
                    let full_path = if src_path.is_absolute() {
                        src_path.clone()
                    } else {
                        project_path.join(src_path)
                    };
                    if full_path.exists() {
                        if let Ok(content) = fs::read_to_string(&full_path) {
                            index
                                .source_files
                                .insert(g, SourceFile::new(full_path, content));
                        }
                    }
                    g
                }
            };
            remap.insert(*local_id, global_id);
            index
                .contract_to_build_info
                .insert((src_path.clone(), *local_id), bi_hash.clone());
            index
                .path_to_build_infos
                .entry(src_path.clone())
                .or_default()
                .push(bi_hash.clone());
        }

        index.build_info_remaps.insert(bi_hash, remap);
    }

    tracing::debug!(
        "load_source_info: {} source files across {} build-infos ({} unique paths)",
        index.source_files.len(),
        index.build_info_remaps.len(),
        index.path_to_global.len()
    );

    Ok(index)
}

/// Load contract source info from a Foundry artifact, remapping the artifact's
/// source-map file ids into the global id space tracked by `index`.
///
/// `index` is required because the source map's file ids are local to the
/// build-info that compiled the artifact; the artifact's own source path and
/// top-level `id` field are used to identify that build-info.
pub fn load_contract_source_info(
    project_path: &Path,
    contract_name: &str,
    index: &SourceInfoIndex,
) -> Result<Option<(ContractSourceInfo, i32)>> {
    let out_dir = project_path.join("out");

    // Find the artifact file
    for entry in WalkDir::new(&out_dir) {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |e| e == "json")
            && !path.to_string_lossy().contains(".dbg.")
        {
            let file_stem = path.file_stem().unwrap_or_default().to_string_lossy();
            if file_stem == contract_name {
                let content = fs::read_to_string(path)?;
                let artifact: FoundryArtifactFull = serde_json::from_str(&content)
                    .context("Failed to parse artifact")?;

                // Get source map
                let source_map_str = match &artifact.deployed_bytecode.source_map {
                    Some(sm) => sm,
                    None => continue,
                };

                // Parse bytecode
                let bytecode = hex::decode(
                    artifact.deployed_bytecode.object.trim_start_matches("0x")
                ).unwrap_or_default();

                // Resolve the build-info that compiled this artifact and apply
                // its file-id remap. `compilationTarget` (when present) gives
                // us the source path independently of the artifact path.
                let source_path = artifact_source_path(&artifact)
                    .unwrap_or_else(|| path.parent()
                        .and_then(|p| p.file_name())
                        .map(|n| PathBuf::from(n.to_string_lossy().to_string()))
                        .unwrap_or_default());

                let remap = index.remap_for_contract(&source_path, artifact.id);
                let mut locations = parse_source_map(source_map_str);
                for loc in &mut locations {
                    loc.file_id = SourceInfoIndex::apply_remap(remap, loc.file_id);
                }
                let source_map = SourceMap { locations };

                // Get file ID from the (now-remapped) source map's first valid entry
                let file_id = source_map.locations.iter()
                    .find(|loc| loc.file_id >= 0)
                    .map(|loc| loc.file_id)
                    .unwrap_or(-1);

                return Ok(Some((
                    ContractSourceInfo {
                        name: contract_name.to_string(),
                        deployed_bytecode: bytecode,
                        source_map,
                        file_id,
                    },
                    file_id,
                )));
            }
        }
    }

    Ok(None)
}

/// Extract the source path for a Foundry artifact from its
/// `metadata.settings.compilationTarget` (preferred — exact path used by
/// solc) or, failing that, the first key in `metadata.sources`.
fn artifact_source_path(artifact: &FoundryArtifactFull) -> Option<PathBuf> {
    let md = artifact.metadata.as_ref()?;
    if let Some(ct) = md
        .get("settings")
        .and_then(|s| s.get("compilationTarget"))
        .and_then(|c| c.as_object())
    {
        if let Some(k) = ct.keys().next() {
            return Some(PathBuf::from(k));
        }
    }
    if let Some(sources) = md.get("sources").and_then(|s| s.as_object()) {
        if let Some(k) = sources.keys().next() {
            return Some(PathBuf::from(k));
        }
    }
    None
}

/// Generate source coverage from PC coverage (single contract - legacy)
pub fn generate_source_coverage(
    coverage_map: &CoverageMap,
    contract_info: &ContractSourceInfo,
    source_files: &HashMap<i32, SourceFile>,
) -> SourceCoverage {
    let mut result = SourceCoverage::new();

    // First pass: Mark all coverable lines with hits=0
    for loc in &contract_info.source_map.locations {
        if loc.file_id < 0 {
            continue;
        }

        let source = match source_files.get(&loc.file_id) {
            Some(s) => s,
            None => continue,
        };

        let line = source.offset_to_line(loc.start as usize);

        let file_coverage = result.files
            .entry(source.path.clone())
            .or_insert_with(FileCoverage::default);

        file_coverage.line_hits.entry(line).or_insert(0);
    }

    // Second pass: Update hit counts for covered PCs
    let pc_to_idx = build_pc_to_index(&contract_info.deployed_bytecode);

    for (_addr, pc_coverage) in coverage_map {
        for (pc, (stack_bits, _result_bits)) in pc_coverage {
            // Convert PC to instruction index
            let idx = match pc_to_idx.get(pc) {
                Some(i) => *i,
                None => continue,
            };

            // Get source location for this instruction
            let loc = match contract_info.source_map.locations.get(idx) {
                Some(l) => l,
                None => continue,
            };

            // Skip invalid file IDs
            if loc.file_id < 0 {
                continue;
            }

            // Get source file
            let source = match source_files.get(&loc.file_id) {
                Some(s) => s,
                None => continue,
            };

            // Convert byte offset to line number
            let line = source.offset_to_line(loc.start as usize);

            // Calculate hit count from stack_bits (count set bits as rough hit count)
            let hits = stack_bits.count_ones() as usize;

            // Update coverage
            let file_coverage = result.files
                .entry(source.path.clone())
                .or_insert_with(FileCoverage::default);

            *file_coverage.line_hits.entry(line).or_insert(0) += hits.max(1);
        }
    }

    result
}

/// Generate source coverage from PC coverage for ALL contracts
/// This handles external calls (e.g., harness calling LibraryUser)
pub fn generate_source_coverage_multi(
    coverage_map: &CoverageMap,
    codehash_to_source_info: &CodehashToSourceInfo,
    source_files: &HashMap<i32, SourceFile>,
) -> SourceCoverage {
    let mut result = SourceCoverage::new();

    // First pass: Mark all coverable lines from all contracts with source info
    // This ensures we have hits=0 for lines that are coverable but not yet hit
    for (_codehash, contract_info) in codehash_to_source_info {
        for loc in &contract_info.source_map.locations {
            // Skip invalid file IDs
            if loc.file_id < 0 {
                continue;
            }

            // Get source file
            let source = match source_files.get(&loc.file_id) {
                Some(s) => s,
                None => continue,
            };

            // Convert byte offset to line number
            let line = source.offset_to_line(loc.start as usize);

            // Initialize line with 0 hits if not already present
            let file_coverage = result.files
                .entry(source.path.clone())
                .or_insert_with(FileCoverage::default);

            file_coverage.line_hits.entry(line).or_insert(0);
        }
    }

    // Second pass: Process covered PCs and update hit counts
    for (codehash, pc_coverage) in coverage_map {
        // Look up source info for this specific codehash
        let contract_info = match codehash_to_source_info.get(codehash) {
            Some(info) => info,
            None => {
                tracing::debug!(
                    "No source info for codehash {:?} ({} PCs covered)",
                    codehash,
                    pc_coverage.len()
                );
                continue;
            }
        };

        // Build PC -> instruction index mapping for this contract
        let pc_to_idx = build_pc_to_index(&contract_info.deployed_bytecode);

        for (pc, (stack_bits, _result_bits)) in pc_coverage {
            // Convert PC to instruction index
            let idx = match pc_to_idx.get(pc) {
                Some(i) => *i,
                None => continue,
            };

            // Get source location for this instruction
            let loc = match contract_info.source_map.locations.get(idx) {
                Some(l) => l,
                None => continue,
            };

            // Skip invalid file IDs
            if loc.file_id < 0 {
                continue;
            }

            // Get source file
            let source = match source_files.get(&loc.file_id) {
                Some(s) => s,
                None => continue,
            };

            // Convert byte offset to line number
            let line = source.offset_to_line(loc.start as usize);

            // Calculate hit count from stack_bits (count set bits as rough hit count)
            let hits = stack_bits.count_ones() as usize;

            // Update coverage
            let file_coverage = result.files
                .entry(source.path.clone())
                .or_insert_with(FileCoverage::default);

            *file_coverage.line_hits.entry(line).or_insert(0) += hits.max(1);
        }
    }

    result
}

/// Lightweight version - only returns lines that are actually covered
/// O(covered_pcs) instead of O(all_source_locations)
///
/// Use this when you only need to know WHICH lines are covered (e.g., for prefix finding),
/// not the full coverage map with all coverable-but-uncovered lines.
pub fn generate_source_coverage_covered_only(
    coverage_map: &CoverageMap,
    codehash_to_source_info: &CodehashToSourceInfo,
    source_files: &HashMap<i32, SourceFile>,
) -> std::collections::HashSet<(PathBuf, usize)> {
    let mut covered_lines = std::collections::HashSet::new();

    // ONLY process covered PCs - no first pass!
    for (codehash, pc_coverage) in coverage_map {
        // Look up source info for this specific codehash
        let contract_info = match codehash_to_source_info.get(codehash) {
            Some(info) => info,
            None => continue,
        };

        // Build PC -> instruction index mapping for this contract
        let pc_to_idx = build_pc_to_index(&contract_info.deployed_bytecode);

        for (pc, _) in pc_coverage {
            // Convert PC to instruction index
            let idx = match pc_to_idx.get(pc) {
                Some(i) => *i,
                None => continue,
            };

            // Get source location for this instruction
            let loc = match contract_info.source_map.locations.get(idx) {
                Some(l) if l.file_id >= 0 => l,
                _ => continue,
            };

            // Get source file
            let source = match source_files.get(&loc.file_id) {
                Some(s) => s,
                None => continue,
            };

            // Convert byte offset to line number
            let line = source.offset_to_line(loc.start as usize);
            covered_lines.insert((source.path.clone(), line));
        }
    }

    covered_lines
}

/// Save LCOV coverage report
pub fn save_lcov_report(
    coverage: &SourceCoverage,
    project_path: &Path,
    output_dir: &Path,
) -> Result<PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let lcov_content = coverage.to_lcov(project_path);

    fs::create_dir_all(output_dir)?;

    // Use timestamp for filename
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let filename = format!("covered.{}.lcov", timestamp);
    let output_path = output_dir.join(&filename);

    fs::write(&output_path, lcov_content)?;

    Ok(output_path)
}

pub fn save_html_report(
    coverage: &SourceCoverage,
    project_path: &Path,
    output_dir: &Path,
    source_files: &HashMap<i32, SourceFile>,
) -> Result<PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Build file_id_to_path mapping (reverse of what we have)
    let mut file_id_to_path: HashMap<PathBuf, i32> = HashMap::new();
    for (id, sf) in source_files {
        file_id_to_path.insert(sf.path.clone(), *id);
    }

    let html_content = coverage.to_html(project_path, source_files, &file_id_to_path);

    fs::create_dir_all(output_dir)?;

    // Use timestamp for filename
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let filename = format!("covered.{}.html", timestamp);
    let output_path = output_dir.join(&filename);

    fs::write(&output_path, html_content)?;

    Ok(output_path)
}

// ============================================================================
// HTML Report Generation
// ============================================================================

/// Helper struct for HTML file entry
struct HtmlFileEntry {
    file_id: String,
    file_path: String,
    active_lines: usize,
    covered_lines: usize,
    coverage_percentage: usize,
    coverage_color: String,
    coverage_color_alpha: String,
    lines: Vec<HtmlLineEntry>,
}

/// Helper struct for HTML line entry
struct HtmlLineEntry {
    line_number: usize,
    source_code: String,
    row_class: Option<String>,
    hit_count: Option<usize>, // Number of times this line was hit (None = not coverable)
}

/// Convert days since Unix epoch to (year, month, day)
/// Simple algorithm, accurate for dates 1970-2100
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Days since 1970-01-01
    let mut remaining = days as i64;

    // Calculate year
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    // Calculate month and day
    let leap = is_leap_year(year);
    let days_in_months: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for days_in_month in days_in_months {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }

    let day = remaining as u32 + 1;
    (year, month, day)
}

/// Check if a year is a leap year
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Get color based on coverage percentage (Recon brand)
fn get_coverage_color_hsl(percentage: usize) -> String {
    if percentage < 30 {
        "#ff5252".to_string()       // error red
    } else if percentage < 60 {
        "#7160e8".to_string()       // accent purple
    } else if percentage < 80 {
        "#5649b0".to_string()       // dark purple
    } else {
        "#259465".to_string()       // success green
    }
}

/// Get color with alpha based on coverage percentage (Recon brand)
fn get_coverage_color_alpha(percentage: usize) -> String {
    if percentage < 30 {
        "rgba(255, 82, 82, 0.15)".to_string()
    } else if percentage < 60 {
        "rgba(113, 96, 232, 0.15)".to_string()
    } else if percentage < 80 {
        "rgba(86, 73, 176, 0.15)".to_string()
    } else {
        "rgba(37, 148, 101, 0.15)".to_string()
    }
}

/// Generate the full HTML report
fn generate_html_report(
    title: &str,
    total_files: usize,
    total_lines: usize,
    total_covered_lines: usize,
    total_active_lines: usize,
    coverage_percentage: usize,
    timestamp: &str,
    files: Vec<HtmlFileEntry>,
) -> String {
    let coverage_color = get_coverage_color_hsl(coverage_percentage);

    // Build file HTML sections
    let mut files_html = String::new();
    for file in &files {
        let mut lines_html = String::new();
        for line in &file.lines {
            let row_class_attr = line.row_class.as_ref()
                .map(|c| format!(" class=\"{}\"", c))
                .unwrap_or_default();
            // Format hit count: show number for coverable lines, empty for non-coverable
            let hit_display = match line.hit_count {
                Some(0) => "0".to_string(),
                Some(n) => format!("{}×", n),
                None => String::new(),
            };
            let hit_class = match line.hit_count {
                Some(0) => " class=\"hit-zero\"",
                Some(_) => " class=\"hit-positive\"",
                None => "",
            };
            lines_html.push_str(&format!(
                r#"                                <tr{}>
                                    <td class="row-line-number">{}</td>
                                    <td class="row-hit-count"{}>{}</td>
                                    <td class="row-source"><pre>{}</pre></td>
                                </tr>
"#,
                row_class_attr, line.line_number, hit_class, hit_display, line.source_code
            ));
        }

        files_html.push_str(&format!(
            r#"                <div class="source-file" id="{file_id}" data-file-path="{file_path}" data-lines-active="{active_lines}" data-lines-covered="{covered_lines}">
                    <div class="source-file-header">
                        <div class="file-info">
                            <span class="coverage-badge" style="background-color: {coverage_color_alpha}; color: {coverage_color}">
                                {coverage_pct}%
                            </span>
                            <span class="file-name">{file_path}</span>
                        </div>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="chevron-icon">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="source-file-content">
                        <div class="source-file-stats">
                            <span>Lines covered: <strong>{covered_lines} / {active_lines}</strong> ({coverage_pct}%)</span>
                        </div>
                        <div class="code-container">
                            <table class="code-coverage-table">
{lines_html}                            </table>
                        </div>
                    </div>
                </div>
"#,
            file_id = file.file_id,
            file_path = file.file_path,
            active_lines = file.active_lines,
            covered_lines = file.covered_lines,
            coverage_color_alpha = file.coverage_color_alpha,
            coverage_color = file.coverage_color,
            coverage_pct = file.coverage_percentage,
            lines_html = lines_html,
        ));
    }

    // Generate FILE_DATA JSON
    let file_data_json: String = files.iter()
        .map(|f| format!(
            r#"{{"path":"{}","id":"{}","covered":{},"active":{}}}"#,
            f.file_path.replace('\\', "\\\\").replace('"', "\\\""),
            f.file_id,
            f.covered_lines,
            f.active_lines
        ))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;600&family=Roboto:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
{CSS_STYLES}
    </style>
    <script>var FILE_DATA = [{file_data_json}];</script>
</head>
<body>
    <div class="app-container">
        <header>
            <div class="header-content">
                <span class="logo-text">{title}</span>
                <span class="stat-badge">{coverage_percentage}% coverage</span>
            </div>
        </header>

        <div class="split-panel">
            <div id="file-explorer">
                <div class="file-explorer-header">
                    <span class="file-explorer-title">Files</span>
                    <span class="file-count" id="file-count">{total_files} files</span>
                </div>
                <div class="file-search">
                    <input type="text" id="file-search-input" placeholder="Search files..." />
                </div>
                <div class="file-explorer-content">
                    <ul id="file-tree-root" class="file-tree"></ul>
                    <div id="search-no-results" class="search-no-results" style="display:none">No files found</div>
                </div>
            </div>

            <div id="main-view-panel">
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-title">Files</div>
                        <div class="stat-value">{total_files}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Lines</div>
                        <div class="stat-value">{total_lines}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Coverage</div>
                        <div class="stat-value">{coverage_percentage}%</div>
                        <div class="progress-container">
                            <div class="progress-bar" style="width:{coverage_percentage}%;background:{coverage_color}"></div>
                        </div>
                        <div style="margin-top:0.5rem">
                            <span class="stat-badge">{total_covered_lines} / {total_active_lines}</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Actions</div>
                        <div class="button-group">
                            <button class="btn btn-secondary btn-sm" onclick="setAllSourceFilesCollapsed(false)">Expand</button>
                            <button class="btn btn-secondary btn-sm" onclick="setAllSourceFilesCollapsed(true)">Collapse</button>
                        </div>
                    </div>
                </div>
{files_html}
            </div>
        </div>

        <footer>
            Generated by <a href="https://getrecon.xyz" target="_blank">Recon</a> · {timestamp}
        </footer>
    </div>
    <script>
{JS_SCRIPTS}
    </script>
</body>
</html>
"##,
        title = title,
        total_files = total_files,
        total_lines = total_lines,
        total_covered_lines = total_covered_lines,
        total_active_lines = total_active_lines,
        coverage_percentage = coverage_percentage,
        coverage_color = coverage_color,
        timestamp = timestamp,
        files_html = files_html,
        file_data_json = file_data_json,
    )
}

/// CSS styles for the HTML report (Recon brand)
const CSS_STYLES: &str = r#"
:root {
    --bg-primary: #1b1a19;
    --bg-secondary: #262626;
    --bg-tertiary: #2a2a2a;
    --bg-accent: #272533;
    --border-color: rgba(255, 255, 255, 0.1);
    --text-primary: #fafafa;
    --text-secondary: rgba(255, 255, 255, 0.8);
    --text-tertiary: rgba(255, 255, 255, 0.6);
    --accent-primary: #7160e8;
    --accent-light: #dfdbfa;
    --accent-dark: #5649b0;
    --accent-bg: #343147;
    --success-color: #259465;
    --error-color: #ff5252;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

html, body {
    height: 100%;
    overflow: hidden;
}

body {
    font-family: 'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
}

.app-container {
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

header {
    flex-shrink: 0;
    background-color: var(--bg-secondary);
    border-bottom: 1px solid var(--border-color);
    padding: 0.875rem 1.5rem;
}

.header-content {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.logo-text {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--text-primary);
    letter-spacing: -0.01em;
}

.split-panel {
    display: flex;
    flex: 1;
    min-height: 0;
    overflow: hidden;
}

#file-explorer {
    width: 280px;
    min-width: 200px;
    max-width: 400px;
    background-color: var(--bg-secondary);
    border-right: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
}

.file-explorer-header {
    flex-shrink: 0;
    padding: 0.875rem 1rem;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.file-explorer-title {
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.file-count {
    font-size: 0.7rem;
    color: var(--accent-light);
    background: var(--accent-bg);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-weight: 500;
}

.file-search {
    flex-shrink: 0;
    padding: 0.625rem 0.875rem;
    border-bottom: 1px solid var(--border-color);
}

.file-search input {
    width: 100%;
    background-color: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    color: var(--text-primary);
    font-size: 0.8125rem;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
}

.file-search input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 2px rgba(113, 96, 232, 0.2);
}

.file-search input::placeholder {
    color: var(--text-tertiary);
}

.file-explorer-content {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 0.5rem 0;
}

.file-tree {
    list-style: none;
    font-size: 0.8125rem;
    padding: 0 0.5rem;
}

.file-tree ul {
    list-style: none;
    margin: 0;
    padding-left: 1rem;
}

.tree-folder {
    margin: 2px 0;
}

.tree-folder-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.625rem;
    cursor: pointer;
    border-radius: 6px;
    user-select: none;
    transition: background-color 0.1s;
}

.tree-folder-header:hover {
    background-color: var(--bg-tertiary);
}

.tree-icon {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
    color: var(--text-tertiary);
}

.tree-file:hover .tree-icon,
.tree-folder-header:hover .tree-icon {
    color: var(--accent-light);
}

.tree-chevron {
    width: 12px;
    height: 12px;
    color: var(--text-tertiary);
    transition: transform 0.15s ease;
    flex-shrink: 0;
}

.tree-folder:not(.collapsed) > .tree-folder-header .tree-chevron {
    transform: rotate(90deg);
}

.tree-folder.collapsed > .tree-children {
    display: none;
}

.tree-file {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.625rem 0.375rem 1.75rem;
    cursor: pointer;
    border-radius: 6px;
    transition: background-color 0.1s;
}

.tree-file:hover {
    background-color: var(--bg-tertiary);
}

.tree-coverage {
    font-weight: 600;
    font-size: 0.7rem;
    min-width: 32px;
    text-align: right;
    flex-shrink: 0;
    font-family: 'Roboto Mono', monospace;
}

.tree-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
}

.tree-file:hover .tree-name,
.tree-folder-header:hover .tree-name {
    color: var(--text-primary);
}

.tree-visibility {
    margin-left: auto;
    padding: 0.25rem;
    border-radius: 4px;
    cursor: pointer;
    opacity: 0;
    transition: opacity 0.15s, background-color 0.15s;
}

.tree-folder-header:hover .tree-visibility {
    opacity: 1;
}

.tree-visibility:hover {
    background-color: var(--bg-primary);
}

.eye-icon {
    width: 16px;
    height: 16px;
    color: var(--text-tertiary);
    display: block;
}

.tree-visibility:hover .eye-icon {
    color: var(--accent-light);
}

.eye-closed {
    display: none;
}

.tree-folder.hidden-children .eye-open {
    display: none;
}

.tree-folder.hidden-children .eye-closed {
    display: block;
}

.tree-folder.hidden-children .tree-children {
    opacity: 0.4;
}

.tree-file.file-hidden {
    opacity: 0.35;
}

.source-file.file-hidden {
    display: none;
}

.search-no-results {
    padding: 2rem 1rem;
    text-align: center;
    color: var(--text-tertiary);
    font-size: 0.8125rem;
}

#main-view-panel {
    flex: 1;
    overflow-y: auto;
    padding: 1.5rem;
    min-width: 0;
    background-color: var(--bg-primary);
}

.stats-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.stat-card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 1.25rem;
}

.stat-title {
    font-size: 0.7rem;
    font-weight: 500;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
}

.stat-value {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary);
    font-family: 'Roboto Mono', monospace;
}

.stat-badge {
    display: inline-block;
    padding: 0.25rem 0.625rem;
    background-color: var(--accent-bg);
    border-radius: 5px;
    font-size: 0.75rem;
    color: var(--accent-light);
    font-weight: 500;
}

.progress-container {
    height: 6px;
    background-color: var(--bg-tertiary);
    border-radius: 3px;
    margin-top: 0.75rem;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    border-radius: 3px;
    background: linear-gradient(90deg, var(--accent-primary), var(--accent-light));
    transition: width 0.3s ease;
}

.button-group {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.btn {
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
    border: none;
}

.btn-secondary {
    background-color: var(--accent-bg);
    color: var(--accent-light);
}

.btn-secondary:hover {
    background-color: #3b384f;
}

.btn-sm {
    padding: 0.4rem 0.75rem;
    font-size: 0.75rem;
}

.source-file {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    margin-bottom: 0.875rem;
    overflow: hidden;
}

.source-file-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.875rem 1rem;
    background-color: var(--bg-tertiary);
    cursor: pointer;
    user-select: none;
    transition: background-color 0.1s;
}

.source-file-header:hover {
    background-color: #333;
}

.file-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.coverage-badge {
    padding: 0.25rem 0.625rem;
    border-radius: 5px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'Roboto Mono', monospace;
}

.file-name {
    font-family: 'Roboto Mono', monospace;
    font-size: 0.8125rem;
    color: var(--text-secondary);
}

.chevron-icon {
    color: var(--text-tertiary);
    transition: transform 0.2s ease;
}

.source-file.collapsed .chevron-icon {
    transform: rotate(-90deg);
}

.source-file.collapsed .source-file-content {
    display: none;
}

.source-file-content {
    border-top: 1px solid var(--border-color);
}

.source-file-stats {
    padding: 0.625rem 1rem;
    font-size: 0.8rem;
    color: var(--text-tertiary);
    border-bottom: 1px solid var(--border-color);
    background-color: var(--bg-secondary);
}

.code-container {
    overflow-x: auto;
}

.code-coverage-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Roboto Mono', monospace;
    font-size: 0.8rem;
    line-height: 1.6;
}

.code-coverage-table tr {
    border-bottom: 1px solid var(--border-color);
}

.code-coverage-table tr:last-child {
    border-bottom: none;
}

.row-line-number {
    width: 45px;
    padding: 0 0.625rem;
    text-align: right;
    color: var(--text-tertiary);
    background-color: var(--bg-tertiary);
    user-select: none;
    vertical-align: top;
    border-right: 1px solid var(--border-color);
}

.row-hit-count {
    width: 50px;
    padding: 0 0.5rem;
    text-align: right;
    color: var(--text-tertiary);
    background-color: var(--bg-tertiary);
    user-select: none;
    vertical-align: top;
    font-size: 0.7rem;
    border-right: 1px solid var(--border-color);
}

.row-hit-count.hit-zero {
    color: var(--error-color);
    font-weight: 600;
}

.row-hit-count.hit-positive {
    color: var(--success-color);
    font-weight: 600;
}

.row-source {
    padding: 0 1rem;
    white-space: pre;
}

.row-source pre {
    margin: 0;
    font-family: inherit;
    font-size: inherit;
}

.row-line-covered {
    background-color: rgba(37, 148, 101, 0.12);
}

.row-line-uncovered {
    background-color: rgba(255, 82, 82, 0.12);
}

footer {
    flex-shrink: 0;
    background-color: var(--bg-secondary);
    border-top: 1px solid var(--border-color);
    padding: 0.625rem 1.5rem;
    text-align: center;
    font-size: 0.75rem;
    color: var(--text-tertiary);
}

footer a {
    color: var(--accent-light);
    text-decoration: none;
}

footer a:hover {
    color: var(--accent-primary);
    text-decoration: underline;
}
"#;

/// JavaScript for the HTML report - uses FILE_DATA embedded in HTML
const JS_SCRIPTS: &str = r#"
// FILE_DATA is embedded in the HTML as a global variable

// Toggle source file collapse
document.querySelectorAll('.source-file-header').forEach(header => {
    header.addEventListener('click', () => {
        header.parentElement.classList.toggle('collapsed');
    });
});

// Set all source files collapsed state
function setAllSourceFilesCollapsed(collapsed) {
    document.querySelectorAll('.source-file').forEach(file => {
        file.classList.toggle('collapsed', collapsed);
    });
}

// Set empty (0% coverage) source files collapsed state
function setEmptySourceFilesCollapsed(collapsed) {
    document.querySelectorAll('.source-file').forEach(file => {
        if ((parseInt(file.dataset.linesCovered) || 0) === 0) {
            file.classList.toggle('collapsed', collapsed);
        }
    });
}

// Simple substring search (fast)
function searchMatch(query, path) {
    return path.toLowerCase().includes(query.toLowerCase());
}

// File search
const searchInput = document.getElementById('file-search-input');
const noResults = document.getElementById('search-no-results');
let searchTimeout = null;

function performSearch(query) {
    if (!query) {
        // Show all
        document.querySelectorAll('.source-file').forEach(f => f.style.display = '');
        document.querySelectorAll('.tree-folder, .tree-file').forEach(f => {
            f.style.display = '';
            if (f.classList.contains('tree-folder')) f.classList.add('collapsed');
        });
        if (noResults) noResults.style.display = 'none';
        return;
    }

    const matchingPaths = new Set();
    const matchingIds = new Set();
    FILE_DATA.forEach(f => {
        if (searchMatch(query, f.path)) {
            matchingPaths.add(f.path);
            matchingIds.add(f.id);
        }
    });

    // Update main panel
    document.querySelectorAll('.source-file').forEach(file => {
        file.style.display = matchingIds.has(file.id) ? '' : 'none';
    });

    // Hide all tree items first
    document.querySelectorAll('.tree-folder, .tree-file').forEach(f => {
        f.style.display = 'none';
        if (f.classList.contains('tree-folder')) f.classList.add('collapsed');
    });

    // Show matching files and their ancestors
    document.querySelectorAll('.tree-file').forEach(item => {
        if (matchingPaths.has(item.dataset.path)) {
            item.style.display = '';
            let parent = item.parentElement;
            while (parent) {
                const folder = parent.closest('.tree-folder');
                if (folder) {
                    folder.style.display = '';
                    folder.classList.remove('collapsed');
                    parent = folder.parentElement;
                } else break;
            }
        }
    });

    if (noResults) noResults.style.display = matchingPaths.size === 0 ? 'block' : 'none';
}

if (searchInput) {
    searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => performSearch(e.target.value.trim()), 100);
    });
}

// Build file tree from embedded FILE_DATA
function buildFileTree() {
    const root = document.getElementById('file-tree-root');
    if (!root || !window.FILE_DATA) return;

    // Build tree structure
    const tree = { _c: 0, _a: 0 }; // _c=covered, _a=active

    FILE_DATA.forEach(file => {
        const parts = file.path.split('/');
        let node = tree;
        parts.forEach((part, i) => {
            if (i === parts.length - 1) {
                node[part] = { _f: file };
            } else {
                if (!node[part]) node[part] = { _c: 0, _a: 0 };
                node[part]._c += file.covered;
                node[part]._a += file.active;
                node = node[part];
            }
        });
    });

    // Recon brand colors: red(0%) -> purple(50%) -> green(100%)
    const getColor = pct => {
        if (pct < 30) return '#ff5252';      // error red
        if (pct < 60) return '#7160e8';      // accent purple
        if (pct < 80) return '#5649b0';      // dark purple
        return '#259465';                     // success green
    };

    function renderTree(node) {
        const entries = Object.entries(node)
            .filter(([k]) => !k.startsWith('_'))
            .sort((a, b) => {
                const aFile = '_f' in a[1], bFile = '_f' in b[1];
                if (aFile !== bFile) return aFile ? 1 : -1;
                return a[0].localeCompare(b[0]);
            });

        return entries.map(([name, val]) => {
            const isFile = '_f' in val;
            const pct = isFile
                ? (val._f.active > 0 ? Math.round(val._f.covered / val._f.active * 100) : 0)
                : (val._a > 0 ? Math.round(val._c / val._a * 100) : 0);
            const color = getColor(pct);

            if (isFile) {
                return `<li class="tree-file" data-path="${val._f.path}" data-id="${val._f.id}">
                    <svg class="tree-icon" viewBox="0 0 16 16" fill="none">
                        <path d="M3 1.5h6.5L13 5v9.5H3v-13z" stroke="currentColor" stroke-width="1.2"/>
                        <path d="M9.5 1.5V5H13" stroke="currentColor" stroke-width="1.2"/>
                    </svg>
                    <span class="tree-coverage" style="color:${color}">${pct}%</span>
                    <span class="tree-name">${name}</span>
                </li>`;
            }
            return `<li class="tree-folder collapsed">
                <div class="tree-folder-header">
                    <svg class="tree-chevron" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M6 4l4 4-4 4"/>
                    </svg>
                    <svg class="tree-icon" viewBox="0 0 16 16" fill="none">
                        <path d="M1.5 3.5h4l1.5 2h7.5v8h-13v-10z" stroke="currentColor" stroke-width="1.2"/>
                    </svg>
                    <span class="tree-coverage" style="color:${color}">${pct}%</span>
                    <span class="tree-name">${name}</span>
                    <span class="tree-visibility" title="Toggle visibility">
                        <svg class="eye-icon eye-open" viewBox="0 0 24 24" fill="none">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.5"/>
                            <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/>
                        </svg>
                        <svg class="eye-icon eye-closed" viewBox="0 0 24 24" fill="none">
                            <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" stroke="currentColor" stroke-width="1.5"/>
                            <path d="M1 1l22 22" stroke="currentColor" stroke-width="1.5"/>
                        </svg>
                    </span>
                </div>
                <ul class="tree-children">${renderTree(val)}</ul>
            </li>`;
        }).join('');
    }

    root.innerHTML = renderTree(tree);

    // Event delegation
    root.addEventListener('click', e => {
        // Handle visibility toggle
        const visibility = e.target.closest('.tree-visibility');
        if (visibility) {
            e.stopPropagation();
            const folder = visibility.closest('.tree-folder');
            folder.classList.toggle('hidden-children');

            // Toggle visibility of files in main panel
            const isHidden = folder.classList.contains('hidden-children');
            folder.querySelectorAll('.tree-file').forEach(file => {
                file.classList.toggle('file-hidden', isHidden);
                const sourceFile = document.getElementById(file.dataset.id);
                if (sourceFile) sourceFile.classList.toggle('file-hidden', isHidden);
            });
            return;
        }

        const file = e.target.closest('.tree-file');
        if (file && !file.classList.contains('file-hidden')) {
            const target = document.getElementById(file.dataset.id);
            if (target) {
                target.classList.remove('collapsed');
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            return;
        }
        const header = e.target.closest('.tree-folder-header');
        if (header) header.parentElement.classList.toggle('collapsed');
    });

    // Update file count
    const countEl = document.getElementById('file-count');
    if (countEl) countEl.textContent = FILE_DATA.length + ' files';
}

// Initialize
buildFileTree();
setAllSourceFilesCollapsed(true);
"#;

// Simple directory walker (matches the one in foundry.rs)
struct WalkDir {
    stack: Vec<PathBuf>,
}

impl WalkDir {
    fn new(path: &Path) -> Self {
        Self {
            stack: vec![path.to_path_buf()],
        }
    }
}

struct DirEntry {
    path: PathBuf,
}

impl DirEntry {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Iterator for WalkDir {
    type Item = Result<DirEntry, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(path) = self.stack.pop() {
            if path.is_dir() {
                match fs::read_dir(&path) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            self.stack.push(entry.path());
                        }
                    }
                    Err(e) => return Some(Err(e)),
                }
            } else if path.is_file() {
                return Some(Ok(DirEntry { path }));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_map() {
        let source_map = "65:541:12:-:0;;;88:21";
        let locations = parse_source_map(source_map);

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].start, 65);
        assert_eq!(locations[0].length, 541);
        assert_eq!(locations[0].file_id, 12);

        // Second entry inherits file_id
        assert_eq!(locations[1].start, 65);
        assert_eq!(locations[1].length, 541);
        assert_eq!(locations[1].file_id, 12);
    }

    #[test]
    fn test_offset_to_line() {
        let content = "line1\nline2\nline3\n".to_string();
        let source = SourceFile::new(PathBuf::from("test.sol"), content);

        assert_eq!(source.offset_to_line(0), 1);  // start of line1
        assert_eq!(source.offset_to_line(5), 1);  // end of line1 (newline)
        assert_eq!(source.offset_to_line(6), 2);  // start of line2
        assert_eq!(source.offset_to_line(12), 3); // start of line3
    }

    #[test]
    fn test_build_pc_to_index() {
        // Simple bytecode: PUSH1 0x60, STOP
        let bytecode = vec![0x60, 0x00, 0x00];
        let mapping = build_pc_to_index(&bytecode);

        assert_eq!(mapping.get(&0), Some(&0)); // PUSH1 at PC 0 is index 0
        assert_eq!(mapping.get(&2), Some(&1)); // STOP at PC 2 is index 1
    }

    /// Two build-info JSONs reuse the same numeric file id (5) for *different*
    /// source paths. The naive merge would overwrite — this test pins down
    /// that the new index keeps each build-info's id space separate, assigns
    /// distinct global ids, and remap_for_contract returns the right map.
    #[test]
    fn test_load_source_info_multi_build_info_id_collision() {
        let tmp = tempdir_unique();
        let project = tmp.join("proj");
        let bi_dir = project.join("out").join("build-info");
        fs::create_dir_all(&bi_dir).unwrap();

        // Two real source files with different content so we can verify which
        // SourceFile got loaded for each global id.
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join("src/A.sol"), "// A\n").unwrap();
        fs::write(project.join("src/B.sol"), "// B\n").unwrap();

        // Build-info "aaaa" assigns id=5 → src/A.sol
        let bi_a = serde_json::json!({
            "source_id_to_path": { "5": "src/A.sol" }
        });
        fs::write(bi_dir.join("aaaa.json"), bi_a.to_string()).unwrap();
        // Build-info "bbbb" assigns id=5 → src/B.sol  (collides!)
        let bi_b = serde_json::json!({
            "source_id_to_path": { "5": "src/B.sol" }
        });
        fs::write(bi_dir.join("bbbb.json"), bi_b.to_string()).unwrap();

        let index = load_source_info(&project).expect("load_source_info");

        // Each path must have its own global id.
        let g_a = index.path_to_global.get(&PathBuf::from("src/A.sol")).copied();
        let g_b = index.path_to_global.get(&PathBuf::from("src/B.sol")).copied();
        assert!(g_a.is_some() && g_b.is_some());
        assert_ne!(g_a, g_b, "distinct paths must have distinct global ids");

        // Both source files must be loaded under their global ids.
        let sa = index.source_files.get(&g_a.unwrap()).unwrap();
        let sb = index.source_files.get(&g_b.unwrap()).unwrap();
        assert!(sa.content.contains("// A"));
        assert!(sb.content.contains("// B"));

        // remap_for_contract must pick the right build-info per (path, local_id).
        let remap_a = index
            .remap_for_contract(&PathBuf::from("src/A.sol"), Some(5))
            .expect("A remap");
        assert_eq!(remap_a.get(&5).copied(), g_a, "A's local id 5 -> A's global id");

        let remap_b = index
            .remap_for_contract(&PathBuf::from("src/B.sol"), Some(5))
            .expect("B remap");
        assert_eq!(remap_b.get(&5).copied(), g_b, "B's local id 5 -> B's global id");
    }

    /// A stale build-info file older than BUILD_INFO_FRESH_WINDOW_SECS must be
    /// ignored — it would otherwise contribute file ids that no current
    /// artifact references, polluting the global remap.
    #[test]
    fn test_load_source_info_drops_stale_build_info() {
        let tmp = tempdir_unique();
        let project = tmp.join("proj");
        let bi_dir = project.join("out").join("build-info");
        fs::create_dir_all(&bi_dir).unwrap();
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join("src/Fresh.sol"), "// fresh\n").unwrap();
        fs::write(project.join("src/Stale.sol"), "// stale\n").unwrap();

        let fresh = serde_json::json!({
            "source_id_to_path": { "0": "src/Fresh.sol" }
        });
        let stale = serde_json::json!({
            "source_id_to_path": { "0": "src/Stale.sol" }
        });
        fs::write(bi_dir.join("fresh.json"), fresh.to_string()).unwrap();
        fs::write(bi_dir.join("stale.json"), stale.to_string()).unwrap();

        // Backdate the stale file far enough to fall outside the freshness window.
        let stale_path = bi_dir.join("stale.json");
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(BUILD_INFO_FRESH_WINDOW_SECS + 60);
        let old_ft = filetime::FileTime::from_system_time(old);
        filetime::set_file_mtime(&stale_path, old_ft).unwrap();

        let index = load_source_info(&project).expect("load_source_info");
        assert!(index.path_to_global.contains_key(&PathBuf::from("src/Fresh.sol")));
        assert!(
            !index.path_to_global.contains_key(&PathBuf::from("src/Stale.sol")),
            "stale build-info should have been dropped"
        );
    }

    /// Helper: create a unique temp directory.
    fn tempdir_unique() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("recon_src_test_{}_{}", nanos, n));
        fs::create_dir_all(&p).unwrap();
        p
    }
}

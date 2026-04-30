//! Coverage inspectors
//!
//! Runtime coverage tracking using REVM inspectors.
//! Provides CombinedInspector for main fuzzing loop and TracingWithCheatcodes for detailed tracing.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use revm::{
    context_interface::ContextTr,
    interpreter::interpreter_types::{InputsTr, InterpreterTypes, Jumps, LegacyBytecode, StackTr},
    interpreter::{
        CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    Inspector,
};
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::cheatcodes::{CheatcodeInspector, CheatcodeState, HEVM_ADDRESS};

/// JUMPI opcode (0x57) - conditional branch
const OP_JUMPI: u8 = 0x57;

/// Known CBOR metadata prefixes in Solidity bytecode
/// These mark the start of the metadata section which is identical
/// for all deployments of the same contract (regardless of constructor args/immutables)
const KNOWN_METADATA_PREFIXES: &[&[u8]] = &[
    // a2 64 "ipfs" 0x58 0x22 (solc >= 0.6.0) - most common, check first
    &[0xa2, 0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22],
    // a2 65 "bzzr1" 0x58 0x20 (solc >= 0.5.11)
    &[0xa2, 0x65, 98, 122, 122, 114, 49, 0x58, 0x20],
    // a2 65 "bzzr0" 0x58 0x20 (solc >= 0.5.9)
    &[0xa2, 0x65, 98, 122, 122, 114, 48, 0x58, 0x20],
    // a1 65 "bzzr0" 0x58 0x20 (solc <= 0.5.8)
    &[0xa1, 0x65, 98, 122, 122, 114, 48, 0x58, 0x20],
];

/// Fixed size for metadata extraction - prefix (8 bytes) + IPFS/bzzr hash (34 bytes) = 42 bytes
/// This ensures consistent hashing regardless of constructor arguments or trailing data
const METADATA_FIXED_SIZE: usize = 42;

/// Maximum range from end of bytecode to search for metadata
/// Real CBOR metadata is typically in the last ~100-200 bytes, but we allow more for safety
/// This prevents false matches from immutable data or other code that happens to contain
/// bytes matching the metadata prefix pattern
const METADATA_SEARCH_RANGE: usize = 300;

/// EIP-1167 Minimal Proxy pattern detection
/// Format: 363d3d373d3d3d363d73 + <20-byte implementation address> + 5af43d82803e903d91602b57fd5bf3
/// Total length: 10 + 20 + 15 = 45 bytes
const EIP1167_PREFIX: &[u8] = &[0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
const EIP1167_SUFFIX: &[u8] = &[0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3];
const EIP1167_LENGTH: usize = 45;

/// Check if bytecode is an EIP-1167 minimal proxy and extract the implementation address
/// Returns Some(implementation_address) if it's a minimal proxy, None otherwise
fn extract_eip1167_implementation(bytecode: &[u8]) -> Option<Address> {
    // Check exact length
    if bytecode.len() != EIP1167_LENGTH {
        return None;
    }

    // Check prefix (first 10 bytes)
    if !bytecode.starts_with(EIP1167_PREFIX) {
        return None;
    }

    // Check suffix (last 15 bytes)
    if !bytecode.ends_with(EIP1167_SUFFIX) {
        return None;
    }

    // Extract implementation address (bytes 10-30)
    let impl_bytes: [u8; 20] = bytecode[10..30].try_into().ok()?;
    Some(Address::from(impl_bytes))
}

/// Extract a fixed-size portion of the metadata section from bytecode
/// This is the same for all deployments of a contract, regardless of constructor args or immutables
///
/// IMPORTANT: For init code, constructor args may be appended AFTER the metadata.
/// We extract only a FIXED portion of the metadata (prefix + IPFS hash = 42 bytes)
/// to ensure the hash matches regardless of what follows the metadata.
///
/// Returns a fixed-size metadata portion if found, otherwise falls back to bytecode length hash
fn extract_bytecode_metadata(bytecode: &[u8]) -> &[u8] {
    // Only search the last METADATA_SEARCH_RANGE bytes to avoid false matches
    // from immutable data or code that happens to contain metadata-like bytes
    let search_start = bytecode.len().saturating_sub(METADATA_SEARCH_RANGE);
    let search_slice = &bytecode[search_start..];

    for prefix in KNOWN_METADATA_PREFIXES {
        if let Some(relative_pos) = rfind_subsequence(search_slice, prefix) {
            // Convert relative position to absolute position in original bytecode
            let metadata_start = search_start + relative_pos;
            let available = bytecode.len() - metadata_start;
            let extract_len = METADATA_FIXED_SIZE.min(available);
            return &bytecode[metadata_start..metadata_start + extract_len];
        }
    }
    // No metadata found - fall back to full bytecode (will likely use length-based fallback)
    bytecode
}

/// Find last occurrence of a subsequence in a byte slice (search from end)
fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    // Search backwards from end
    for i in (0..=(haystack.len() - needle.len())).rev() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Compute the metadata hash for a bytecode
/// This is used as a key to look up the compile-time codehash
pub fn compute_metadata_hash(bytecode: &[u8]) -> B256 {
    let metadata = extract_bytecode_metadata(bytecode);
    keccak256(metadata)
}

/// Build a map from metadata hash to compile-time codehash
/// This is built from all compiled contracts at startup
/// Include BOTH creation (init) bytecode AND deployed (runtime) bytecode
/// This ensures coverage is tracked correctly for constructor execution, not just runtime
///
/// NOTE: Multiple contracts may share the same metadata hash (e.g., if they inherit from
/// the same base contract). We store (bytecode_len, codehash) pairs and use bytecode length
/// as a tiebreaker at runtime.
pub fn build_codehash_map(contracts: &[crate::foundry::CompiledContract]) -> MetadataToCodehash {
    let mut map: MetadataToCodehash = HashMap::new();

    for contract in contracts {
        // Add deployed (runtime) bytecode
        if !contract.deployed_bytecode.is_empty() {
            let compile_time_codehash = keccak256(&contract.deployed_bytecode);
            let metadata_hash = compute_metadata_hash(&contract.deployed_bytecode);
            let bytecode_len = contract.deployed_bytecode.len();

            map.entry(metadata_hash)
                .or_insert_with(Vec::new)
                .push((bytecode_len, compile_time_codehash));

            tracing::debug!(
                "CodehashMap (deployed): {} -> metadata={:?} -> codehash={:?} (len={})",
                contract.name,
                metadata_hash,
                compile_time_codehash,
                bytecode_len
            );
        }

        // Also add creation (init) bytecode
        // This ensures constructor coverage is tracked with the correct codehash,
        // not grouped by bytecode length in the fallback path
        if !contract.bytecode.is_empty() {
            let creation_codehash = keccak256(&contract.bytecode);
            let creation_metadata_hash = compute_metadata_hash(&contract.bytecode);
            let bytecode_len = contract.bytecode.len();

            map.entry(creation_metadata_hash)
                .or_insert_with(Vec::new)
                .push((bytecode_len, creation_codehash));

            tracing::debug!(
                "CodehashMap (creation): {} -> metadata={:?} -> codehash={:?} (len={})",
                contract.name,
                creation_metadata_hash,
                creation_codehash,
                bytecode_len
            );
        }
    }

    let total_entries: usize = map.values().map(|v| v.len()).sum();
    tracing::info!("Built codehash map with {} metadata hashes, {} total entries", map.len(), total_entries);
    map
}

/// Look up codehash by metadata hash and bytecode length
/// Uses bytecode length as tiebreaker when multiple contracts share the same metadata hash
pub fn lookup_codehash(map: &MetadataToCodehash, metadata_hash: &B256, bytecode_len: usize) -> Option<B256> {
    map.get(metadata_hash).and_then(|entries| {
        // First try exact length match
        for &(len, codehash) in entries {
            if len == bytecode_len {
                return Some(codehash);
            }
        }
        // If no exact match, find closest length (for cases with constructor args)
        // Constructor args add bytes, so look for the closest shorter length
        let mut best_match: Option<(usize, B256)> = None;
        for &(len, codehash) in entries {
            if len <= bytecode_len {
                match best_match {
                    None => best_match = Some((len, codehash)),
                    Some((best_len, _)) if len > best_len => best_match = Some((len, codehash)),
                    _ => {}
                }
            }
        }
        best_match.map(|(_, codehash)| codehash)
    })
}

/// Fallback lookup by bytecode length when metadata lookup fails
/// This handles contracts with immutables where metadata might differ
/// Returns the codehash if exactly one contract matches the length, otherwise None
pub fn lookup_codehash_by_length(map: &MetadataToCodehash, bytecode_len: usize) -> Option<B256> {
    let mut matches: Vec<B256> = Vec::new();
    for entries in map.values() {
        for &(len, codehash) in entries {
            if len == bytecode_len {
                if !matches.contains(&codehash) {
                    matches.push(codehash);
                }
            }
        }
    }
    // Only return if exactly one unique contract matches
    // Multiple matches means ambiguity - fall back to length-based grouping
    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

/// Compute a deterministic codehash for an EIP-1167 minimal proxy
/// Groups all proxies pointing to the same implementation address together
///
/// This is correct semantically because:
/// 1. The proxy's bytecode is identical except for the implementation address
/// 2. Coverage of the proxy setup code is the same for all proxies
/// 3. Actual execution happens via DELEGATECALL to the implementation (tracked separately)
pub fn compute_eip1167_codehash(impl_address: Address) -> B256 {
    // Create a deterministic hash that includes both:
    // 1. A marker to identify this as an EIP-1167 proxy
    // 2. The implementation address
    let mut data = Vec::with_capacity(32 + 20);
    // Use a fixed prefix to distinguish from regular codehashes
    data.extend_from_slice(b"EIP1167_PROXY_IMPL:");
    data.extend_from_slice(impl_address.as_slice());
    keccak256(&data)
}

/// Try to resolve a codehash for bytecode, with special handling for EIP-1167 minimal proxies
/// This is the main entry point for codehash resolution during coverage tracking
///
/// Resolution order:
/// 1. Check if it's an EIP-1167 minimal proxy -> use implementation-based codehash
/// 2. Try metadata hash lookup
/// 3. Try length-based fallback
/// 4. Return None (caller will use final fallback)
pub fn resolve_codehash(
    map: &MetadataToCodehash,
    bytecode: &[u8],
) -> Option<B256> {
    // Check for EIP-1167 minimal proxy FIRST
    // These are 45-byte contracts that delegate to an implementation
    if let Some(impl_address) = extract_eip1167_implementation(bytecode) {
        let codehash = compute_eip1167_codehash(impl_address);
        tracing::debug!(
            "EIP-1167 proxy detected: impl={:?} -> codehash={:?}",
            impl_address, codehash
        );
        return Some(codehash);
    }

    // Standard resolution: metadata hash lookup
    let metadata_hash = compute_metadata_hash(bytecode);
    if let Some(codehash) = lookup_codehash(map, &metadata_hash, bytecode.len()) {
        return Some(codehash);
    }

    // Fallback: length-based lookup
    lookup_codehash_by_length(map, bytecode.len())
}

/// Map from metadata hash to list of (bytecode_len, codehash) pairs
/// Multiple contracts may share the same metadata hash, so we store all of them
/// and use bytecode length as a tiebreaker at runtime
pub type MetadataToCodehash = HashMap<B256, Vec<(usize, B256)>>;

/// Inspector for collecting coverage information
#[derive(Debug, Default, Clone)]
pub struct CoverageInspector {
    /// Set of executed (address, pc, stack_depth)
    pub touched: HashSet<(Address, usize, u64)>,
}

impl CoverageInspector {
    pub fn new() -> Self {
        Self {
            touched: HashSet::new(),
        }
    }
}

impl<CTX, INTR: InterpreterTypes> Inspector<CTX, INTR> for CoverageInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // Use Jumps trait to access PC
        let pc = interp.bytecode.pc();

        // Use InputsTr to get the target address (contract being executed)
        let contract_addr = interp.input.target_address();

        // Use StackTr to get the stack length
        let stack_len = interp.stack.len() as u64;

        if !contract_addr.is_zero() {
            self.touched.insert((contract_addr, pc, stack_len));
        }
    }
}

/// Minimal PC counter for deployment coverage tracking
///
/// This inspector ONLY tracks (codehash, pc, call_depth) tuples.
/// It doesn't handle cheatcodes - use with tuple inspector: (CheatcodeInspector, DeploymentPcCounter)
/// This ensures cheatcode handling is identical to standalone CheatcodeInspector.
#[derive(Debug)]
pub struct DeploymentPcCounter {
    /// Touched PCs: (codehash, pc, call_depth)
    pub touched: Vec<(B256, usize, usize)>,
    /// Call depth tracking
    pub call_depth: usize,
    /// Metadata hash -> compile-time codehash mapping
    metadata_to_codehash: std::sync::Arc<parking_lot::RwLock<MetadataToCodehash>>,
    /// Cache: bytecode pointer -> codehash (fast lookup within single tx)
    bytecode_ptr_cache: HashMap<(usize, usize), B256>,
    /// Stack of codehashes for nested CREATE contexts
    /// When CREATE is called, we compute and push the init code's codehash
    /// This ensures we track the correct codehash during constructor execution
    create_codehash_stack: Vec<B256>,
}

impl DeploymentPcCounter {
    pub fn new(metadata_to_codehash: std::sync::Arc<parking_lot::RwLock<MetadataToCodehash>>) -> Self {
        Self {
            touched: Vec::with_capacity(TOUCHED_INITIAL_CAPACITY),
            call_depth: 0,
            metadata_to_codehash,
            bytecode_ptr_cache: HashMap::new(),
            create_codehash_stack: Vec::new(),
        }
    }
}

impl<CTX, INTR: InterpreterTypes> Inspector<CTX, INTR> for DeploymentPcCounter {
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        let pc = interp.bytecode.pc();
        let depth = self.call_depth;

        // If we're in a CREATE context, use the pre-computed codehash from the stack
        // This is more reliable because we compute it from the exact init_code passed to CREATE
        // (before any potential issues with how REVM presents the bytecode in the interpreter)
        let codehash = if let Some(&create_codehash) = self.create_codehash_stack.last() {
            // We're inside a CREATE - use the codehash computed in create()
            create_codehash
        } else {
            // Not in a CREATE context - compute codehash from interpreter's bytecode
            let contract_addr = interp.input.target_address();

            // Log first step at each depth to verify we're tracking correctly
            if pc == 0 {
                let bytecode = interp.bytecode.bytecode_slice();
                tracing::debug!(
                    "DeploymentPcCounter::step first PC (non-CREATE): depth={}, addr={:?}, bytecode_len={}",
                    depth, contract_addr, bytecode.len()
                );
            }

            if contract_addr.is_zero() {
                return; // Skip if no valid address
            }

            let bytecode = interp.bytecode.bytecode_slice();
            let bytecode_ptr = bytecode.as_ptr() as usize;
            let bytecode_len = bytecode.len();
            let ptr_key = (bytecode_ptr, bytecode_len);

            if let Some(&cached) = self.bytecode_ptr_cache.get(&ptr_key) {
                cached
            } else {
                // Use unified resolve_codehash which handles EIP-1167 proxies and standard contracts
                let codehash = {
                    let map = self.metadata_to_codehash.read();
                    resolve_codehash(&map, bytecode)
                }
                .unwrap_or_else(|| {
                    // Final fallback: use bytecode length as pseudo-hash
                    tracing::debug!(
                        "DeploymentPcCounter fallback: bytecode_len={}, addr={:?}",
                        bytecode.len(), contract_addr
                    );
                    let mut len_bytes = [0u8; 32];
                    len_bytes[24..32].copy_from_slice(&(bytecode.len() as u64).to_be_bytes());
                    B256::from(len_bytes)
                });
                self.bytecode_ptr_cache.insert(ptr_key, codehash);
                codehash
            }
        };

        self.touched.push((codehash, pc, depth));
    }

    fn call(&mut self, _context: &mut CTX, _inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.call_depth += 1;
        None // Let CheatcodeInspector handle cheatcodes
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, _outcome: &mut CallOutcome) {
        if self.call_depth > 0 {
            self.call_depth -= 1;
        }
    }

    fn create(
        &mut self,
        _context: &mut CTX,
        inputs: &mut revm::interpreter::CreateInputs,
    ) -> Option<revm::interpreter::CreateOutcome> {
        self.call_depth += 1;

        // Compute the codehash for this CREATE's init code
        // This is pushed onto a stack so we know which codehash to use during constructor execution
        let init_code = inputs.init_code();
        let init_code_len = init_code.len();
        let codehash = {
            let map = self.metadata_to_codehash.read();
            // Use unified resolve_codehash which handles EIP-1167 proxies and standard contracts
            resolve_codehash(&map, &init_code)
        }
        .unwrap_or_else(|| {
            // Final fallback: use init code LENGTH as pseudo-codehash
            // This groups contracts by size, preventing explosion from different constructor args
            tracing::debug!(
                "DeploymentPcCounter::create fallback: init_code_len={}",
                init_code_len
            );
            let mut len_bytes = [0u8; 32];
            len_bytes[24..32].copy_from_slice(&(init_code_len as u64).to_be_bytes());
            B256::from(len_bytes)
        });

        tracing::debug!(
            "DeploymentPcCounter::create: depth={}, init_code_len={}, codehash={:?}",
            self.call_depth,
            init_code_len,
            codehash
        );

        self.create_codehash_stack.push(codehash);
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &revm::interpreter::CreateInputs,
        outcome: &mut revm::interpreter::CreateOutcome,
    ) {
        tracing::debug!(
            "DeploymentPcCounter::create_end: depth={}, result={:?}, address={:?}",
            self.call_depth,
            outcome.result.result,
            outcome.address
        );

        // Pop the codehash for this CREATE context
        self.create_codehash_stack.pop();

        if self.call_depth > 0 {
            self.call_depth -= 1;
        }
    }
}

/// Coverage tracking mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageMode {
    /// Track every opcode (full coverage, slower)
    Full,
    /// Only track branch points: JUMPI and JUMPDEST (faster, less granular)
    Branch,
}

impl CoverageMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "branch" | "branches" | "fast" => CoverageMode::Branch,
            _ => CoverageMode::Full,
        }
    }
}

/// Initial capacity for touched Vec - avoids reallocation for most transactions
/// A typical transaction touches 1000-10000 opcodes, pre-allocate for common case
pub const TOUCHED_INITIAL_CAPACITY: usize = 4096;

/// Selector keccak256("Panic(uint256)")[..4] — Solidity 0.8+ Panic revert prefix.
const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

/// Combined inspector for coverage tracking AND cheatcode handling
#[derive(Debug, Clone)]
pub struct CombinedInspector {
    /// Coverage data: (codehash, pc, call_depth)
    pub touched: Vec<(B256, usize, u64)>,
    /// Current call depth (number of nested CALL frames)
    /// Incremented in call(), decremented in call_end()
    /// this tracks `length vm.frames`
    pub call_depth: u64,
    /// Set to true if any sub-call (any depth) reverted with `Panic(0x01)` —
    /// the encoding solc uses for `assert(false)` in 0.8+. Detection is a
    /// 4-byte selector + single-byte panic-code compare in `call_end`.
    pub nested_panic_1: bool,
    /// Set to true if any sub-call halted with `InvalidFEOpcode` — the older
    /// encoding for `assert` (0xfe). Detection is one match arm in `call_end`.
    pub nested_invalid_fe: bool,
    /// Cache of metadata_hash -> compile-time codehash
    /// NOTE: We key by metadata_hash (bytecode identity) not address, because for DELEGATECALL
    /// the same address can execute different bytecode (caller vs library)
    pub codehash_cache: HashMap<B256, B256>,
    /// Fast cache: (bytecode_ptr, bytecode_len) -> codehash
    /// This avoids re-computing metadata_hash for the same bytecode in a single tx
    /// The bytecode pointer is stable within a single interpreter execution
    pub bytecode_ptr_cache: HashMap<(usize, usize), B256>,
    /// Map from metadata hash to compile-time codehash (shared, built at startup)
    pub metadata_to_codehash: std::sync::Arc<parking_lot::RwLock<MetadataToCodehash>>,
    /// Cheatcode state
    pub cheatcode: CheatcodeInspector,
    /// Addresses created during the current transaction (internal CREATE/CREATE2)
    pub created_addresses: Vec<Address>,
    /// Coverage mode: Full (every opcode) or Branch (only JUMPI/JUMPDEST)
    pub coverage_mode: CoverageMode,
    /// Stack of codehashes for nested CREATE contexts
    /// When CREATE is called, we compute and push the init code's codehash
    /// This ensures we track the correct codehash during constructor execution
    pub create_codehash_stack: Vec<B256>,
}

impl Default for CombinedInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl CombinedInspector {
    pub fn new() -> Self {
        Self {
            touched: Vec::with_capacity(TOUCHED_INITIAL_CAPACITY),
            call_depth: 0, // Start at 0, incremented on first call
            nested_panic_1: false,
            nested_invalid_fe: false,
            codehash_cache: HashMap::new(),
            bytecode_ptr_cache: HashMap::new(),
            metadata_to_codehash: std::sync::Arc::new(parking_lot::RwLock::new(HashMap::new())),
            cheatcode: CheatcodeInspector::new(),
            created_addresses: Vec::new(),
            coverage_mode: CoverageMode::Full, // Default to full coverage
            create_codehash_stack: Vec::new(),
        }
    }

    /// Create with a shared metadata-to-codehash map
    pub fn with_codehash_map(
        metadata_to_codehash: std::sync::Arc<parking_lot::RwLock<MetadataToCodehash>>,
    ) -> Self {
        Self {
            touched: Vec::with_capacity(TOUCHED_INITIAL_CAPACITY),
            call_depth: 0,
            nested_panic_1: false,
            nested_invalid_fe: false,
            codehash_cache: HashMap::new(),
            bytecode_ptr_cache: HashMap::new(),
            metadata_to_codehash,
            cheatcode: CheatcodeInspector::new(),
            created_addresses: Vec::new(),
            coverage_mode: CoverageMode::Full,
            create_codehash_stack: Vec::new(),
        }
    }

    /// Set coverage mode (Full or Branch)
    pub fn set_coverage_mode(&mut self, mode: CoverageMode) {
        self.coverage_mode = mode;
    }

    /// Get the cheatcode state
    pub fn cheatcode_state(&self) -> &CheatcodeState {
        &self.cheatcode.state
    }

    /// Get mutable cheatcode state
    pub fn cheatcode_state_mut(&mut self) -> &mut CheatcodeState {
        &mut self.cheatcode.state
    }

    /// Set context for vm.generateCalls() cheatcode
    /// The cheatcode uses gen_abi_call_m directly - identical to main fuzzer.
    /// `return_masks` lets the caller restrict which subset of generated
    /// calls is returned to the harness; pass `Vec::new()` for capture mode.
    pub fn set_generate_calls_context(
        &mut self,
        fuzzable_functions: Vec<(alloy_primitives::FixedBytes<4>, String, Vec<alloy_dyn_abi::DynSolType>)>,
        gen_dict: std::sync::Arc<abi::types::GenDict>,
        rng_seed: u64,
        return_masks: Vec<Option<Vec<bool>>>,
    ) {
        use crate::cheatcodes::GenerateCallsContext;
        self.cheatcode.generate_calls_ctx = Some(GenerateCallsContext {
            fuzzable_functions,
            gen_dict,
            rng_seed,
            call_count: 0,
            call_index: 0,
            return_masks,
            captured_records: Vec::new(),
        });
    }

    /// Clear the generate_calls context
    pub fn clear_generate_calls(&mut self) {
        self.cheatcode.generate_calls_ctx = None;
    }

    /// Clear touched coverage data while retaining allocated capacity
    /// Call this at the start of each transaction for efficient reuse
    #[inline]
    pub fn clear_touched(&mut self) {
        self.touched.clear();
    }

    /// Reset inspector for a new transaction (clears all per-tx state)
    /// More efficient than creating a new inspector
    #[inline]
    pub fn reset_for_new_tx(&mut self) {
        self.touched.clear();
        self.bytecode_ptr_cache.clear();
        self.created_addresses.clear();
        self.call_depth = 0;
        self.create_codehash_stack.clear();
        self.nested_panic_1 = false;
        self.nested_invalid_fe = false;
    }
}

/// JUMPDEST opcode (0x5B) - jump target
const OP_JUMPDEST: u8 = 0x5B;

impl<CTX: ContextTr, INTR: InterpreterTypes> Inspector<CTX, INTR> for CombinedInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, context: &mut CTX) {
        // Delegate to cheatcode inspector for opcode tracking (warp/roll)
        self.cheatcode.step(interp, context);

        // Get the opcode being executed FIRST for early exit in branch mode
        let pc = interp.bytecode.pc();
        let bytecode = interp.bytecode.bytecode_slice();
        let opcode = if pc < bytecode.len() { bytecode[pc] } else { 0 };

        // FAST PATH: In branch mode, skip non-branch opcodes entirely
        // This provides significant speedup by avoiding codehash lookup for most opcodes
        if self.coverage_mode == CoverageMode::Branch {
            // Only track JUMPI (conditional branch) and JUMPDEST (branch target)
            if opcode != OP_JUMPI && opcode != OP_JUMPDEST {
                return;
            }
        }

        // NOT stack_len (EVM operand stack 0-1024) which was causing 44% coverage gap
        let depth = self.call_depth;

        // If we're in a CREATE context, use the pre-computed codehash from the stack
        // CRITICAL: During CREATE, the address and deployed bytecode aren't available yet,
        // so we use the codehash computed in create() from the init_code
        let codehash = if let Some(&create_codehash) = self.create_codehash_stack.last() {
            // We're inside a CREATE - use the codehash computed in create()
            // Log first step at each depth to verify we're tracking correctly
            if pc == 0 {
                tracing::debug!(
                    "CombinedInspector::step first PC (CREATE context): depth={}, codehash={:?}, bytecode_len={}",
                    depth, create_codehash, bytecode.len()
                );
            }
            create_codehash
        } else {
            // Not in a CREATE context - compute codehash from interpreter's bytecode
            let contract_addr = interp.input.target_address();

            if contract_addr.is_zero() {
                return; // Skip if no valid address
            }

            // FAST PATH: Use bytecode pointer + length as cache key
            // This avoids expensive metadata hash computation on every step
            // The bytecode slice pointer is stable within a single interpreter context
            let bytecode_ptr = bytecode.as_ptr() as usize;
            let bytecode_len = bytecode.len();
            let ptr_key = (bytecode_ptr, bytecode_len);

            if let Some(&cached) = self.bytecode_ptr_cache.get(&ptr_key) {
                // Fast path: bytecode pointer already seen in this tx
                cached
            } else {
                // Slow path: resolve codehash from bytecode
                // Use unified resolve_codehash which handles EIP-1167 proxies and standard contracts
                let codehash = {
                    let map = self.metadata_to_codehash.read();
                    resolve_codehash(&map, bytecode)
                }
                .unwrap_or_else(|| {
                    // Final fallback: use bytecode length as pseudo-codehash
                    // This groups contracts by size, preventing explosion from proxies
                    tracing::trace!(
                        "Unknown contract (final fallback): bytecode_len={}, addr={:?}",
                        bytecode_len, contract_addr
                    );
                    // Use bytecode length as the hash - contracts of same size are grouped
                    let mut len_bytes = [0u8; 32];
                    len_bytes[24..32].copy_from_slice(&(bytecode.len() as u64).to_be_bytes());
                    B256::from(len_bytes)
                });

                // Cache by bytecode metadata hash for reuse
                let metadata_hash = compute_metadata_hash(bytecode);
                self.codehash_cache.insert(metadata_hash, codehash);

                // Cache by pointer for fast lookup on subsequent steps
                self.bytecode_ptr_cache.insert(ptr_key, codehash);
                codehash
            }
        };

        // PERF: Use push instead of insert - deduplication happens at end of tx
        self.touched.push((codehash, pc, depth));
    }

    fn step_end(&mut self, interp: &mut Interpreter<INTR>, context: &mut CTX) {
        // Delegate to cheatcode inspector for warp/roll handling
        self.cheatcode.step_end(interp, context);
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Increment call depth for coverage tracking (length vm.frames)
        self.call_depth += 1;

        let target = inputs.target_address;

        tracing::debug!(
            "Inspector call() to {:?}, caller: {:?}, depth: {}",
            target,
            inputs.caller,
            self.call_depth
        );

        // Check if this is a call to the cheatcode address
        if target == HEVM_ADDRESS {
            // Extract bytes from CallInput using the context (handles SharedBuffer properly)
            let input_data: Bytes = inputs.input.bytes(context);

            tracing::debug!(
                "HEVM call detected, input len: {}, selector: 0x{}",
                input_data.len(),
                if input_data.len() >= 4 {
                    hex::encode(&input_data[..4])
                } else {
                    "short".to_string()
                }
            );

            // Handle startPrank/stopPrank directly here since they need caller context
            if input_data.len() >= 4 {
                use crate::cheatcodes::{startPrankCall, stopPrankCall};
                use alloy_sol_types::SolCall;

                let selector = &input_data[..4];

                // Handle startPrank(address)
                if selector == startPrankCall::SELECTOR {
                    if let Ok(decoded) = startPrankCall::abi_decode(&input_data) {
                        // Check if already pranking - Foundry reverts in this case
                        if self.cheatcode.state.start_prank_caller.is_some() {
                            // Decrement call_depth since we incremented it at the start
                            if self.call_depth > 0 {
                                self.call_depth -= 1;
                            }
                            return Some(CallOutcome {
                                result: InterpreterResult {
                                    result: InstructionResult::Revert,
                                    output: Bytes::from_static(b"already pranking"),
                                    gas: Gas::new(inputs.gas_limit),
                                },
                                memory_offset: inputs.return_memory_offset.clone(),
                                precompile_call_logs: vec![],
                                was_precompile_called: false,
                            });
                        }

                        self.cheatcode.state.start_prank_caller = Some(decoded.msgSender);
                        self.cheatcode.state.prank_origin = Some(inputs.caller);

                        // Decrement call_depth since we're returning early
                        if self.call_depth > 0 {
                            self.call_depth -= 1;
                        }
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Return,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                            precompile_call_logs: vec![],
                            was_precompile_called: false,
                        });
                    }
                }

                // Handle stopPrank()
                if selector == stopPrankCall::SELECTOR {
                    self.cheatcode.state.start_prank_caller = None;
                    self.cheatcode.state.prank_origin = None;

                    // Decrement call_depth since we're returning early
                    if self.call_depth > 0 {
                        self.call_depth -= 1;
                    }
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::new(),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                    });
                }

                // Handle deal(address, uint256) - requires DB access
                use crate::cheatcodes::dealCall;
                use revm::context_interface::JournalTr;
                if selector == dealCall::SELECTOR {
                    if let Ok(decoded) = dealCall::abi_decode(&input_data) {
                        // Load account mutably from the journal
                        if let Ok(mut account_load) = context.journal_mut().load_account_mut(decoded.who) {
                            account_load.data.set_balance(decoded.newBalance);
                        }

                        // Decrement call_depth since we're returning early
                        if self.call_depth > 0 {
                            self.call_depth -= 1;
                        }
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Return,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                            precompile_call_logs: vec![],
                            was_precompile_called: false,
                        });
                    }
                }

                // Handle etch(address, bytes) - requires DB access to set bytecode
                use crate::cheatcodes::etchCall;
                use revm::bytecode::Bytecode;
                if selector == etchCall::SELECTOR {
                    if let Ok(decoded) = etchCall::abi_decode(&input_data) {
                        // First, ensure the account exists in the journal by loading it
                        // This creates the account if it doesn't exist
                        let _ = context.journal_mut().load_account_mut(decoded.target);

                        // Now use journal's set_code_with_hash to properly set bytecode
                        let bytecode = Bytecode::new_raw(decoded.code.clone());
                        let code_hash = bytecode.hash_slow();
                        context.journal_mut().set_code_with_hash(decoded.target, bytecode, code_hash);
                        tracing::debug!("vm.etch: set code at {:?}, len={}, hash={:?}", decoded.target, decoded.code.len(), code_hash);

                        // Decrement call_depth since we're returning early
                        if self.call_depth > 0 {
                            self.call_depth -= 1;
                        }
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Return,
                                output: Bytes::new(),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                            precompile_call_logs: vec![],
                            was_precompile_called: false,
                        });
                    }
                }
            }

            // Handle generateCalls(uint256 count) - return pre-generated calldatas
            if input_data.len() >= 4 {
                use crate::cheatcodes::generateCallsCall;
                use alloy_sol_types::SolCall;
                if &input_data[..4] == generateCallsCall::SELECTOR {
                    if let Ok(decoded) = generateCallsCall::abi_decode(&input_data) {
                        let count = decoded.count.try_into().unwrap_or(0usize);
                        let output = self.cheatcode.generate_calls(count);

                        // Decrement call_depth since we're returning early
                        if self.call_depth > 0 {
                            self.call_depth -= 1;
                        }
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Return,
                                output,
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                            precompile_call_logs: vec![],
                            was_precompile_called: false,
                        });
                    }
                }
            }

            // Handle other cheatcodes - if we recognize it, return the result
            // If we don't recognize it, still return success (empty bytes) to prevent revert
            let result = self
                .cheatcode
                .handle_cheatcode(&input_data)
                .unwrap_or_else(|| {
                    // Unknown cheatcode - log it and return empty success
                    if input_data.len() >= 4 {
                        tracing::debug!(
                            "Unknown cheatcode selector: 0x{}",
                            hex::encode(&input_data[..4])
                        );
                    }
                    Bytes::new()
                });

            tracing::debug!(
                "After HEVM call, prank_caller: {:?}",
                self.cheatcode.state.prank_caller
            );

            // Decrement call_depth since we're returning early for cheatcodes
            if self.call_depth > 0 {
                self.call_depth -= 1;
            }

            // Return success with the result - NEVER revert on HEVM calls
            return Some(CallOutcome {
                result: InterpreterResult {
                    result: InstructionResult::Return,
                    output: result,
                    gas: Gas::new(inputs.gas_limit),
                },
                memory_offset: inputs.return_memory_offset.clone(),
                precompile_call_logs: vec![],
                was_precompile_called: false,
            });
        }

        // Apply prank if set (modify the caller for the next call)
        // IMPORTANT: Only apply prank if there's NO value transfer
        // When value is transferred, REVM expects the caller account to be loaded in the journal
        // Changing caller to a pranked address that isn't loaded causes REVM to panic
        // This also matches Foundry's behavior where prank only affects msg.sender,
        // not the actual source of transferred funds
        let transfers_value = inputs.transfers_value();

        if !transfers_value {
            // Check for single-use prank first
            if let Some(prank_addr) = self.cheatcode.state.prank_caller.take() {
                // Single prank - apply once and clear
                inputs.caller = prank_addr;
            } else if let Some(prank_addr) = self.cheatcode.state.start_prank_caller {
                // Persistent prank - ONLY apply if caller matches prank_origin
                // prank_origin is the address that called startPrank
                // This ensures internal calls (e.g., Spoke -> Hub) are NOT pranked
                // Only direct calls FROM the pranking contract should be affected
                if self.cheatcode.state.prank_origin == Some(inputs.caller) {
                    inputs.caller = prank_addr;
                }
            }
        } else {
            // Value transfer - consume single prank but don't apply it
            // This ensures single-use prank is "used up" even on value-transferring calls
            if self.cheatcode.state.prank_caller.is_some() {
                let _ = self.cheatcode.state.prank_caller.take();
            }
        }

        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        // Cheap any-depth assertion-failure detection. Both flags are sticky
        // for the tx — once set they stay set. Cost: at most a 4-byte selector
        // + 1-byte panic-code compare per CALL frame.
        use revm::interpreter::InstructionResult;
        match outcome.result.result {
            // assert(false) on solc 0.8+ → Revert with Panic(uint256) selector + code 1.
            InstructionResult::Revert if !self.nested_panic_1 => {
                let out = &outcome.result.output;
                if out.len() >= 4 + 32
                    && out[..4] == PANIC_SELECTOR
                    && out[4 + 31] == 1
                {
                    self.nested_panic_1 = true;
                }
            }
            // Pre-0.8 `assert(false)` compiles to INVALID (0xFE).
            InstructionResult::InvalidFEOpcode | InstructionResult::OpcodeNotFound => {
                self.nested_invalid_fe = true;
            }
            _ => {}
        }

        // Decrement call depth when call returns
        if self.call_depth > 0 {
            self.call_depth -= 1;
        }
    }

    fn create(
        &mut self,
        context: &mut CTX,
        inputs: &mut revm::interpreter::CreateInputs,
    ) -> Option<revm::interpreter::CreateOutcome> {
        // Increment depth for consistency, though CREATE implies a new context
        self.call_depth += 1;

        // Compute the codehash for this CREATE's init code
        // This is pushed onto a stack so we know which codehash to use during constructor execution
        // CRITICAL: During CREATE, the address and deployed bytecode aren't known yet,
        // so we must pre-compute the codehash from the init_code passed to CREATE
        let init_code = &inputs.init_code();
        let init_code_len = init_code.len();
        let codehash = {
            let map = self.metadata_to_codehash.read();
            // Use unified resolve_codehash which handles EIP-1167 proxies and standard contracts
            resolve_codehash(&map, init_code)
        }
        .unwrap_or_else(|| {
            // Final fallback: use init code LENGTH as pseudo-codehash
            // This groups contracts by size, preventing explosion from different constructor args
            tracing::debug!(
                "CombinedInspector::create fallback: init_code_len={}",
                init_code_len
            );
            let mut len_bytes = [0u8; 32];
            len_bytes[24..32].copy_from_slice(&(init_code_len as u64).to_be_bytes());
            B256::from(len_bytes)
        });

        tracing::debug!(
            "CombinedInspector::create: depth={}, init_code_len={}, codehash={:?}",
            self.call_depth,
            init_code_len,
            codehash
        );

        self.create_codehash_stack.push(codehash);

        // Delegate to cheatcode inspector for prank handling on CREATE
        <CheatcodeInspector as Inspector<CTX, INTR>>::create(&mut self.cheatcode, context, inputs)
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &revm::interpreter::CreateInputs,
        outcome: &mut revm::interpreter::CreateOutcome,
    ) {
        tracing::debug!(
            "CombinedInspector::create_end: depth={}, result={:?}, address={:?}",
            self.call_depth,
            outcome.result.result,
            outcome.address
        );

        // Pop the codehash for this CREATE context
        self.create_codehash_stack.pop();

        if self.call_depth > 0 {
            self.call_depth -= 1;
        }

        // Capture successfully created addresses
        if let InstructionResult::Return = outcome.result.result {
            if let Some(addr) = outcome.address {
                tracing::debug!("CombinedInspector captured created address: {:?}", addr);
                self.created_addresses.push(addr);
            }
        }
    }
}

/// Coverage map type: Codehash -> PC -> (StackBits, ResultBits)
/// Using codehash (keccak256 of bytecode) instead of address ensures
/// the same contract deployed to different addresses is tracked once
pub type CoverageMap = HashMap<B256, HashMap<usize, (u64, u64)>>;

/// Calculate coverage statistics
/// Returns (points, numCodehashes)
pub fn coverage_stats(
    init_coverage: &CoverageMap,
    runtime_coverage: &CoverageMap,
) -> (usize, usize) {
    // Combine both coverage maps
    let mut all_points = 0usize;
    let mut codehashes = HashSet::new();

    for (codehash, pcs) in init_coverage.iter().chain(runtime_coverage.iter()) {
        codehashes.insert(*codehash);
        all_points += pcs.len();
    }

    (all_points, codehashes.len())
}

/// Calculate coverage points (total unique PC locations hit)
pub fn coverage_points(coverage: &CoverageMap) -> usize {
    coverage.values().map(|pcs| pcs.len()).sum()
}

/// Get number of unique contracts covered
pub fn num_codehashes(coverage: &CoverageMap) -> usize {
    coverage.len()
}

/// Combined inspector for tracing with cheatcode support
/// This wraps CheatcodeInspector + TracingInspector and ensures both get called properly.
/// Unlike the tuple impl which uses or_else for call(), this ALWAYS calls both inspectors.
pub struct TracingWithCheatcodes {
    pub cheatcode: CheatcodeInspector,
    pub tracing: revm_inspectors::tracing::TracingInspector,
    /// Storage reads captured during execution: (address, slot) -> value
    pub storage_reads: HashMap<(Address, U256), U256>,
    /// Pending SLOAD: slot being loaded (set in step, value captured in step_end)
    pending_sload: Option<(Address, U256)>,
    /// PCs hit during execution: (codehash, pc) for solver closest approach tracking
    pub pcs_hit: Vec<(B256, usize)>,
    /// Current contract codehash being executed
    current_codehash: Option<B256>,
}

impl TracingWithCheatcodes {
    pub fn new(config: revm_inspectors::tracing::TracingInspectorConfig) -> Self {
        Self {
            cheatcode: CheatcodeInspector::new(),
            tracing: revm_inspectors::tracing::TracingInspector::new(config),
            storage_reads: HashMap::new(),
            pending_sload: None,
            pcs_hit: Vec::new(),
            current_codehash: None,
        }
    }

    pub fn into_traces(self) -> revm_inspectors::tracing::CallTraceArena {
        self.tracing.into_traces()
    }

    /// Get captured storage reads from this transaction
    pub fn get_storage_reads(&self) -> &HashMap<(Address, U256), U256> {
        &self.storage_reads
    }

    /// Take storage reads (consumes the map)
    pub fn take_storage_reads(&mut self) -> HashMap<(Address, U256), U256> {
        std::mem::take(&mut self.storage_reads)
    }

    /// Get PCs hit during execution (for solver closest approach tracking)
    pub fn get_pcs_hit(&self) -> &[(B256, usize)] {
        &self.pcs_hit
    }

    /// Take PCs hit (consumes the vec)
    pub fn take_pcs_hit(&mut self) -> Vec<(B256, usize)> {
        std::mem::take(&mut self.pcs_hit)
    }
}

// Implement Inspector for TracingWithCheatcodes with concrete bounds that match mainnet context
use revm_inspector::JournalExt;
use revm::interpreter::interpreter::EthInterpreter;

impl<CTX> revm::Inspector<CTX, EthInterpreter> for TracingWithCheatcodes
where
    CTX: ContextTr<Journal: JournalExt>,
{
    fn initialize_interp(
        &mut self,
        interp: &mut Interpreter<EthInterpreter>,
        context: &mut CTX,
    ) {
        self.cheatcode.initialize_interp(interp, context);
        self.tracing.initialize_interp(interp, context);
    }

    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, context: &mut CTX) {
        self.cheatcode.step(interp, context);
        self.tracing.step(interp, context);

        // PC tracking: capture current PC for solver closest approach analysis
        let pc = interp.bytecode.pc();

        // Compute codehash from bytecode if we haven't already
        // This is more reliable than trying to get it from call() context
        if self.current_codehash.is_none() {
            let bytecode = interp.bytecode.bytecode_slice();
            if !bytecode.is_empty() {
                self.current_codehash = Some(keccak256(bytecode));
            }
        }

        // Track PC with current codehash (if we know it)
        if let Some(codehash) = self.current_codehash {
            self.pcs_hit.push((codehash, pc));
        }

        // SLOAD tracking: capture storage slot being loaded for solver state resolution
        let bytecode = interp.bytecode.bytecode_slice();
        let opcode = if pc < bytecode.len() { bytecode[pc] } else { 0 };

        const OP_SLOAD: u8 = 0x54;
        if opcode == OP_SLOAD {
            let stack_len = interp.stack.len();
            if stack_len >= 1 {
                let stack_data = interp.stack.data();
                let slot = stack_data[stack_data.len() - 1]; // Top of stack is the slot
                let contract_addr = interp.input.target_address();
                // Record pending SLOAD - we'll capture the value in step_end
                self.pending_sload = Some((contract_addr, slot));
                tracing::trace!(
                    "TracingWithCheatcodes SLOAD: addr={:?}, slot={:?}",
                    contract_addr, slot
                );
            }
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter<EthInterpreter>, context: &mut CTX) {
        self.cheatcode.step_end(interp, context);
        self.tracing.step_end(interp, context);

        // Capture SLOAD result: after SLOAD executes, the value is on top of stack
        if let Some((addr, slot)) = self.pending_sload.take() {
            let stack_len = interp.stack.len();
            if stack_len >= 1 {
                let stack_data = interp.stack.data();
                let value = stack_data[stack_data.len() - 1]; // Top of stack is the loaded value
                self.storage_reads.insert((addr, slot), value);
                tracing::trace!(
                    "TracingWithCheatcodes SLOAD result: addr={:?}, slot={:?}, value={:?}",
                    addr, slot, value
                );
            }
        }
    }

    fn log(&mut self, context: &mut CTX, log: revm::primitives::Log) {
        <CheatcodeInspector as revm::Inspector<CTX, EthInterpreter>>::log(&mut self.cheatcode, context, log.clone());
        self.tracing.log(context, log);
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // ALWAYS call tracing first to start the trace
        // This prevents "can't start step without starting a trace first" panic
        let _tracing_result = self.tracing.call(context, inputs);

        // Track codehash for PC recording
        // We'll capture it in step() when we first execute bytecode since we have access to interp there
        // For now, just mark that we're in a call
        let target = inputs.target_address;
        if !target.is_zero() {
            // Compute codehash from the input bytecode if available
            let input_bytes = inputs.input.bytes(context);
            if !input_bytes.is_empty() {
                // This isn't the bytecode we want - it's the calldata
                // We need to get the codehash from the target contract
                // Set a flag to capture in step()
            }
        }

        // Then let cheatcode handle its logic (modifies inputs.caller for pranks, intercepts HEVM)
        let cheatcode_result = <CheatcodeInspector as revm::Inspector<CTX, EthInterpreter>>::call(&mut self.cheatcode, context, inputs);

        // If cheatcode intercepted (returned Some), use that result
        // Otherwise, tracing's result (which is always None) is used
        cheatcode_result
    }

    fn call_end(&mut self, context: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        <CheatcodeInspector as revm::Inspector<CTX, EthInterpreter>>::call_end(&mut self.cheatcode, context, inputs, outcome);
        self.tracing.call_end(context, inputs, outcome);

        // Clear current codehash when exiting a call
        // Note: this is simplified - nested calls would need a stack
        self.current_codehash = None;
    }

    fn create(
        &mut self,
        context: &mut CTX,
        inputs: &mut revm::interpreter::CreateInputs,
    ) -> Option<revm::interpreter::CreateOutcome> {
        // ALWAYS call tracing first
        let _tracing_result = self.tracing.create(context, inputs);
        <CheatcodeInspector as revm::Inspector<CTX, EthInterpreter>>::create(&mut self.cheatcode, context, inputs)
    }

    fn create_end(
        &mut self,
        context: &mut CTX,
        inputs: &revm::interpreter::CreateInputs,
        outcome: &mut revm::interpreter::CreateOutcome,
    ) {
        <CheatcodeInspector as revm::Inspector<CTX, EthInterpreter>>::create_end(&mut self.cheatcode, context, inputs, outcome);
        self.tracing.create_end(context, inputs, outcome);
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        // Use fully qualified syntax to resolve the context type
        <revm_inspectors::tracing::TracingInspector as revm::Inspector<CTX, EthInterpreter>>::selfdestruct(
            &mut self.tracing, contract, target, value
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfind_subsequence() {
        // Basic case
        let haystack = b"hello world hello";
        let needle = b"hello";
        assert_eq!(rfind_subsequence(haystack, needle), Some(12)); // Last occurrence

        // Not found
        assert_eq!(rfind_subsequence(haystack, b"xyz"), None);

        // Needle longer than haystack
        assert_eq!(rfind_subsequence(b"hi", b"hello"), None);

        // Single byte
        assert_eq!(rfind_subsequence(b"abcabc", b"c"), Some(5));
    }

    #[test]
    fn test_extract_bytecode_metadata_ipfs() {
        // Simulated bytecode with IPFS metadata at end
        // Real metadata starts with: a2 64 69 70 66 73 58 22
        let mut bytecode = vec![0x60, 0x80, 0x60, 0x40]; // Some opcodes
        bytecode.extend_from_slice(&[0xa2, 0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22]); // IPFS prefix
        bytecode.extend_from_slice(&[0x00; 34]); // IPFS hash (34 bytes)
        bytecode.extend_from_slice(&[0x00, 0x33]); // Length suffix

        let metadata = extract_bytecode_metadata(&bytecode);
        // Should return from the a2 64 prefix onwards
        assert!(metadata.starts_with(&[0xa2, 0x64, 0x69, 0x70, 0x66, 0x73]));
    }

    #[test]
    fn test_extract_bytecode_metadata_no_metadata() {
        // Bytecode without any recognized metadata
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52];

        let metadata = extract_bytecode_metadata(&bytecode);
        // Should return full bytecode as fallback
        assert_eq!(metadata, &bytecode[..]);
    }

    #[test]
    fn test_compute_metadata_hash_deterministic() {
        let bytecode = vec![
            0x60, 0x80, 0x60, 0x40, 0x52, 0xa2, 0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22,
        ];

        let hash1 = compute_metadata_hash(&bytecode);
        let hash2 = compute_metadata_hash(&bytecode);

        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_coverage_stats_empty() {
        let init: CoverageMap = HashMap::new();
        let runtime: CoverageMap = HashMap::new();

        let (points, codehashes) = coverage_stats(&init, &runtime);
        assert_eq!(points, 0);
        assert_eq!(codehashes, 0);
    }

    #[test]
    fn test_coverage_stats_combined() {
        let mut init: CoverageMap = HashMap::new();
        let mut runtime: CoverageMap = HashMap::new();

        let codehash1 = B256::repeat_byte(0x01);
        let codehash2 = B256::repeat_byte(0x02);

        // Init coverage: codehash1 with 3 PCs
        let mut pcs1 = HashMap::new();
        pcs1.insert(10, (1u64, 1u64));
        pcs1.insert(20, (1u64, 1u64));
        pcs1.insert(30, (1u64, 1u64));
        init.insert(codehash1, pcs1);

        // Runtime coverage: codehash2 with 2 PCs
        let mut pcs2 = HashMap::new();
        pcs2.insert(100, (1u64, 1u64));
        pcs2.insert(200, (1u64, 1u64));
        runtime.insert(codehash2, pcs2);

        let (points, codehashes) = coverage_stats(&init, &runtime);
        assert_eq!(points, 5); // 3 + 2
        assert_eq!(codehashes, 2);
    }

    #[test]
    fn test_coverage_points() {
        let mut coverage: CoverageMap = HashMap::new();

        let codehash = B256::repeat_byte(0x01);
        let mut pcs = HashMap::new();
        pcs.insert(10, (1u64, 1u64));
        pcs.insert(20, (1u64, 1u64));
        coverage.insert(codehash, pcs);

        assert_eq!(coverage_points(&coverage), 2);
    }

    #[test]
    fn test_num_codehashes() {
        let mut coverage: CoverageMap = HashMap::new();

        coverage.insert(B256::repeat_byte(0x01), HashMap::new());
        coverage.insert(B256::repeat_byte(0x02), HashMap::new());
        coverage.insert(B256::repeat_byte(0x03), HashMap::new());

        assert_eq!(num_codehashes(&coverage), 3);
    }

    #[test]
    fn test_coverage_mode_from_str() {
        assert_eq!(CoverageMode::from_str("branch"), CoverageMode::Branch);
        assert_eq!(CoverageMode::from_str("branches"), CoverageMode::Branch);
        assert_eq!(CoverageMode::from_str("fast"), CoverageMode::Branch);
        assert_eq!(CoverageMode::from_str("BRANCH"), CoverageMode::Branch);
        assert_eq!(CoverageMode::from_str("full"), CoverageMode::Full);
        assert_eq!(CoverageMode::from_str("anything_else"), CoverageMode::Full);
    }

    #[test]
    fn test_combined_inspector_reset() {
        let mut inspector = CombinedInspector::new();

        // Add some data
        inspector.touched.push((B256::ZERO, 100, 1));
        inspector.call_depth = 5;
        inspector.created_addresses.push(Address::ZERO);

        // Reset
        inspector.reset_for_new_tx();

        assert!(inspector.touched.is_empty());
        assert_eq!(inspector.call_depth, 0);
        assert!(inspector.created_addresses.is_empty());
    }

    #[test]
    fn test_combined_inspector_clear_touched_preserves_capacity() {
        let mut inspector = CombinedInspector::new();

        // Add data to grow the vec
        for i in 0..1000 {
            inspector.touched.push((B256::ZERO, i, 1));
        }

        let capacity_before = inspector.touched.capacity();
        inspector.clear_touched();

        // Length should be 0, but capacity preserved
        assert!(inspector.touched.is_empty());
        assert_eq!(inspector.touched.capacity(), capacity_before);
    }
}

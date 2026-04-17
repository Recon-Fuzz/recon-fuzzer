//! WebSocket protocol types for communication between fuzzer and UI
//!
//! These types are serialized as JSON and sent over WebSocket.
//! The TypeScript frontend should have matching type definitions.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

// ============================================================================
// Server -> Client Messages
// ============================================================================

/// Messages sent from the fuzzer server to the UI client
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ServerMessage {
    /// Initial state dump when client connects
    Init(InitPayload),

    /// Periodic state update (sent every ~100ms)
    StateUpdate(StateUpdatePayload),

    /// New coverage discovered event
    NewCoverage(NewCoverageEvent),

    /// New corpus entry added
    NewCorpusEntry(CorpusEntryPayload),

    /// Test state changed
    TestStateChanged(TestStatePayload),

    /// Campaign state changed (started, stopped, finished)
    CampaignStateChanged(CampaignStatePayload),

    /// Worker log message
    WorkerMessage {
        #[serde(rename = "workerId")]
        worker_id: usize,
        message: String,
    },

    /// Response to a command from the client
    CommandResult {
        id: u64,
        success: bool,
        message: String,
    },

    /// Full contract details response
    ContractDetails {
        id: u64,
        contract: Option<ContractInfo>,
    },

    /// Source file content response
    SourceFileContent {
        id: u64,
        file: Option<SourceFile>,
    },

    /// Replay result with execution traces
    ReplayResult {
        id: u64,
        success: bool,
        traces: Vec<TxTraceResult>,
        error: Option<String>,
    },

    /// Error message
    Error {
        message: String,
    },
}

/// Campaign lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum CampaignState {
    /// No campaign running, waiting for user to start one
    #[default]
    Idle,

    /// Campaign is running
    Running,

    /// Campaign is stopping (waiting for shrinking to complete)
    Stopping,

    /// Campaign finished (hit test limit or all tests complete)
    Finished,
}

/// Campaign state change payload
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignStatePayload {
    /// New campaign state
    pub state: CampaignState,

    /// Optional message (e.g., "Campaign finished: all tests passed")
    pub message: Option<String>,

    /// Campaign result summary (if finished)
    pub result: Option<CampaignResult>,
}

/// Campaign result summary
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignResult {
    /// Total calls executed
    pub total_calls: u64,

    /// Total coverage achieved
    pub total_coverage: usize,

    /// Tests passed
    pub tests_passed: usize,

    /// Tests failed
    pub tests_failed: usize,

    /// Corpus size
    pub corpus_size: usize,

    /// Duration in seconds
    pub duration_secs: f64,
}

/// Initial state payload sent when client connects
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitPayload {
    /// Contract summaries (lightweight, no bytecode)
    pub contracts: Vec<ContractSummary>,

    /// Total number of contracts available
    pub total_contracts: usize,

    /// Configuration summary
    pub config: ConfigSummary,

    /// Source files (if available) - only paths, no content for lazy loading
    pub source_files: Vec<SourceFileSummary>,

    /// Current coverage state
    pub coverage: CoverageSnapshot,

    /// Current corpus entries
    pub corpus: Vec<CorpusEntryPayload>,

    /// Test definitions and states
    pub tests: Vec<TestInfo>,

    /// Worker information
    pub workers: Vec<WorkerInfo>,

    /// Current campaign state
    pub campaign_state: CampaignState,

    /// Source-level line coverage (LCOV-style, computed from PC coverage)
    pub source_line_coverage: Vec<SourceLineCoverage>,

    /// PC to source mappings for each contract (for bytecode -> source navigation)
    pub pc_mappings: Vec<ContractPcMapping>,
}

/// Lightweight contract summary (no bytecode) for initial load
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractSummary {
    /// Contract name (e.g., "Token")
    pub name: String,

    /// Full qualified name (e.g., "src/Token.sol:Token")
    pub qualified_name: String,

    /// Deployed address (if deployed)
    pub address: Option<Address>,

    /// Compile-time codehash (for coverage mapping)
    pub codehash: B256,

    /// Number of functions in this contract
    pub function_count: usize,

    /// Whether this contract has echidna_ test functions
    pub has_tests: bool,
}

/// Lightweight source file summary (no content)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFileSummary {
    /// File path relative to project root
    pub path: String,

    /// Language ("solidity", "vyper", etc.)
    pub language: String,

    /// File size in bytes (approximate)
    pub size: usize,
}

/// Contract information for UI display
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractInfo {
    /// Contract name (e.g., "Token")
    pub name: String,

    /// Full qualified name (e.g., "src/Token.sol:Token")
    pub qualified_name: String,

    /// Deployed address (if deployed)
    pub address: Option<Address>,

    /// Compile-time codehash (for coverage mapping)
    pub codehash: B256,

    /// Bytecode as hex string (for client-side disassembly)
    pub bytecode_hex: String,

    /// Runtime bytecode as hex string
    pub deployed_bytecode_hex: String,

    /// Source map (Solc format, if available)
    pub source_map: Option<String>,

    /// Functions in this contract
    pub functions: Vec<FunctionInfo>,
}

/// Function information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionInfo {
    /// Function name
    pub name: String,

    /// Full signature (e.g., "transfer(address,uint256)")
    pub signature: String,

    /// 4-byte selector as hex
    pub selector: String,

    /// Input parameters
    pub inputs: Vec<ParamInfo>,

    /// Output parameters
    pub outputs: Vec<ParamInfo>,

    /// State mutability
    pub state_mutability: String,
}

/// Parameter information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParamInfo {
    /// Parameter name (may be empty)
    pub name: String,

    /// Solidity type (e.g., "uint256", "address")
    #[serde(rename = "type")]
    pub ty: String,
}

/// Source file content
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFile {
    /// File path relative to project root
    pub path: String,

    /// File content
    pub content: String,

    /// Language ("solidity", "vyper", etc.)
    pub language: String,
}

/// Configuration summary for UI display
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    /// Test mode
    pub test_mode: String,

    /// Number of workers
    pub workers: usize,

    /// Test limit (total calls)
    pub test_limit: usize,

    /// Sequence length
    pub seq_len: usize,

    /// Coverage mode
    pub coverage_mode: String,

    /// Contract addresses being tested
    pub target_contracts: Vec<Address>,

    /// Sender addresses
    pub senders: Vec<Address>,

    /// Source folder path from forge config (e.g., "src")
    pub src_folder: String,

    /// Test folder path from forge config (e.g., "test")
    pub test_folder: String,
}

/// Periodic state update
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateUpdatePayload {
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,

    /// Total calls executed across all workers
    pub total_calls: u64,

    /// Total sequences executed
    pub total_sequences: u64,

    /// Total gas consumed
    pub total_gas: u64,

    /// Coverage changes since last update
    pub coverage_delta: CoverageDelta,

    /// Current worker states
    pub workers: Vec<WorkerSnapshot>,

    /// Current revert hotspots (top locations by revert count)
    pub revert_hotspots: Vec<RevertHotspot>,

    /// Current corpus size
    pub corpus_size: usize,

    /// Current campaign state
    pub campaign_state: CampaignState,

    /// Updated source-level line coverage (full snapshot, not delta)
    /// Only sent when coverage has changed
    pub source_line_coverage: Option<Vec<SourceLineCoverage>>,
}

/// Full coverage snapshot
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSnapshot {
    /// Runtime coverage: codehash -> list of covered PCs
    pub runtime: Vec<ContractCoverage>,

    /// Init (constructor) coverage: codehash -> list of covered PCs
    pub init: Vec<ContractCoverage>,

    /// Total covered instruction count
    pub total_instructions: usize,

    /// Total unique contracts covered
    pub total_contracts: usize,
}

/// Coverage for a single contract
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractCoverage {
    /// Codehash as hex string
    pub codehash: String,

    /// List of covered PCs
    pub covered_pcs: Vec<usize>,
}

/// Incremental coverage update (only new PCs since last update)
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CoverageDelta {
    /// New runtime coverage since last update
    pub new_runtime: Vec<ContractCoverage>,

    /// New init coverage since last update
    pub new_init: Vec<ContractCoverage>,

    /// Count of new instructions covered
    pub new_instructions: usize,
}

/// Location that frequently reverts
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevertHotspot {
    /// Contract codehash
    pub codehash: String,

    /// Program counter
    pub pc: usize,

    /// Revert count
    pub count: u32,

    /// Function name (if resolvable)
    pub function_name: Option<String>,

    /// Source location (if available)
    pub source_location: Option<SourceLocation>,
}

/// Source code location
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLocation {
    /// File path
    pub file: String,

    /// Line number (1-indexed)
    pub line: u32,

    /// Column number (1-indexed)
    pub column: u32,
}

// ============================================================================
// Source-Level Coverage (LCOV-style)
// ============================================================================

/// Line coverage for a source file (like LCOV DA entries)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLineCoverage {
    /// File path relative to project root
    pub path: String,

    /// Per-line coverage data
    pub lines: Vec<LineCoverage>,
}

/// Coverage data for a single line
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineCoverage {
    /// Line number (1-indexed)
    pub line: u32,

    /// Number of times this line was hit
    pub hits: u32,
}

// ============================================================================
// PC to Source Mapping (for bytecode -> source navigation)
// ============================================================================

/// PC to source location mapping for a contract
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractPcMapping {
    /// Contract codehash as hex string
    pub codehash: String,

    /// Map of PC -> source location (sparse - only significant PCs)
    pub pc_to_source: Vec<PcSourceEntry>,
}

/// Single PC to source mapping entry
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcSourceEntry {
    /// Program counter
    pub pc: usize,

    /// Source file path
    pub file: String,

    /// Line number (1-indexed)
    pub line: u32,

    /// Column number (1-indexed)
    pub column: u32,

    /// Byte offset in source
    pub offset: u32,

    /// Length of the source range
    pub length: u32,
}

/// Worker snapshot for status display
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSnapshot {
    /// Worker ID
    pub id: usize,

    /// Total calls executed by this worker
    pub calls: u64,

    /// Total sequences executed
    pub sequences: u64,

    /// Total gas consumed
    pub gas: u64,

    /// Whether this is the interactive worker
    pub is_interactive: bool,

    /// Current status
    pub status: WorkerStatus,
}

/// Worker status
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkerStatus {
    /// Normal fuzzing
    Fuzzing,

    /// Shrinking a failure
    Shrinking,

    /// Idle (waiting for commands, interactive worker only)
    Idle,

    /// Executing a user command
    ExecutingCommand { command: String },
}

/// Worker info (static, from init)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerInfo {
    /// Worker ID
    pub id: usize,

    /// Whether this is the interactive worker
    pub is_interactive: bool,
}

/// New coverage event
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewCoverageEvent {
    /// Worker that found the coverage
    pub worker_id: usize,

    /// Number of new instructions covered
    pub new_instructions: usize,

    /// Total instructions covered after this discovery
    pub total_instructions: usize,

    /// Total unique contracts covered
    pub total_contracts: usize,

    /// Corpus size after adding the new entry
    pub corpus_size: usize,
}

/// Corpus entry payload
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusEntryPayload {
    /// Unique ID (hash of sequence)
    pub id: String,

    /// Discovery priority (when this was found)
    pub priority: usize,

    /// Transaction sequence (for display)
    pub sequence: Vec<TxPayload>,

    /// Raw JSON serialized sequence (for replay - matches corpus file format)
    pub sequence_json: String,

    /// Number of unique PCs this entry covers
    pub coverage_contribution: usize,
}

/// Transaction payload for display
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPayload {
    /// Function name (or "create" or "raw")
    pub function: String,

    /// Arguments as human-readable strings
    pub args: Vec<String>,

    /// Sender address
    pub sender: Address,

    /// Target address
    pub target: Address,

    /// ETH value as string
    pub value: String,

    /// Time delay in seconds
    pub delay_time: u64,

    /// Block delay
    pub delay_blocks: u64,
}

/// Transaction trace result for replay
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxTraceResult {
    /// Transaction index in sequence
    pub index: usize,

    /// The transaction that was executed
    pub tx: TxPayload,

    /// Whether the transaction succeeded
    pub success: bool,

    /// Result string (return value or revert reason)
    pub result: String,

    /// Gas used
    pub gas_used: u64,

    /// Call trace entries
    pub call_trace: Vec<CallTraceEntry>,

    /// Events emitted
    pub events: Vec<EventEntry>,

    /// Storage changes
    pub storage_changes: Vec<StorageChange>,
}

/// Single call in the trace
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallTraceEntry {
    /// Call depth (0 = top level)
    pub depth: usize,

    /// Call type (CALL, STATICCALL, DELEGATECALL, CREATE, etc.)
    pub call_type: String,

    /// From address
    pub from: Address,

    /// To address
    pub to: Address,

    /// Function name if known
    pub function: Option<String>,

    /// Input data (abbreviated)
    pub input: String,

    /// Output/return data (abbreviated)
    pub output: String,

    /// Gas used for this call
    pub gas_used: u64,

    /// Success/failure
    pub success: bool,

    /// Revert reason if failed
    pub revert_reason: Option<String>,
}

/// Event emitted during execution
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEntry {
    /// Contract that emitted the event
    pub address: Address,

    /// Event name if known
    pub name: Option<String>,

    /// Decoded topics
    pub topics: Vec<String>,

    /// Decoded data
    pub data: String,
}

/// Storage slot change
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageChange {
    /// Contract address
    pub address: Address,

    /// Contract name if known
    pub contract_name: Option<String>,

    /// Storage slot
    pub slot: String,

    /// Previous value
    pub previous: String,

    /// New value
    pub current: String,
}

/// Test information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestInfo {
    /// Test identifier
    pub id: String,

    /// Test type
    pub test_type: String,

    /// Current state
    pub state: String,

    /// Current value (for optimization tests)
    pub value: Option<String>,

    /// Failure sequence (if failed) - for display
    pub failure_sequence: Option<Vec<TxPayload>>,

    /// Raw JSON serialized failure sequence (for replay - matches corpus file format)
    pub failure_sequence_json: Option<String>,

    /// Worker handling this test
    pub worker_id: Option<usize>,
}

/// Test state changed event
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestStatePayload {
    /// Test ID
    pub id: String,

    /// New state
    pub state: String,

    /// New value (for optimization)
    pub value: Option<String>,

    /// Failure sequence (if just failed) - for display
    pub failure_sequence: Option<Vec<TxPayload>>,

    /// Raw JSON serialized failure sequence (for replay - matches corpus file format)
    pub failure_sequence_json: Option<String>,
}

// ============================================================================
// Client -> Server Messages
// ============================================================================

/// Messages sent from the UI client to the fuzzer server
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ClientMessage {
    /// Inject values into the fuzzer dictionary
    InjectDictionary {
        /// Request ID for response correlation
        id: u64,

        /// Values to inject (hex U256 strings)
        values: Vec<String>,

        /// If true, broadcast to all workers. If false, only interactive worker.
        broadcast: bool,
    },

    /// Inject a transaction sequence into the corpus
    InjectSequence {
        id: u64,
        sequence: Vec<TxRequest>,
    },

    /// Clamp a function argument to a specific value (interactive worker only)
    ClampArgument {
        id: u64,
        function: String,
        #[serde(rename = "paramIdx")]
        param_idx: usize,
        /// JSON-encoded value
        value: String,
    },

    /// Remove a clamp from a function argument
    UnclampArgument {
        id: u64,
        function: String,
        #[serde(rename = "paramIdx")]
        param_idx: usize,
    },

    /// Clear all argument clamps
    ClearAllClamps { id: u64 },

    /// Set target functions for interactive worker (empty = all functions)
    SetTargetFunctions {
        id: u64,
        functions: Vec<String>,
    },

    /// Inject fuzz transaction templates with wildcards
    /// Template: "f(1,?,?) ; g(?,2,5)" - ? for fuzzed, concrete for fixed
    InjectFuzzTransactions {
        id: u64,
        /// Template string like "f(1,?,?) ; g(?,2,5)"
        template: String,
        /// Higher priority = more likely to be selected
        priority: usize,
    },

    /// Clear all fuzz transaction templates
    ClearFuzzTemplates { id: u64 },

    /// Request full state (useful after reconnect)
    RequestFullState { id: u64 },

    /// Ping to keep connection alive
    Ping { id: u64 },

    /// Request full contract details (bytecode, ABI, etc.)
    GetContractDetails {
        id: u64,
        /// Contract name to fetch
        #[serde(rename = "contractName")]
        contract_name: String,
    },

    /// Request source file content
    GetSourceFile {
        id: u64,
        /// File path to fetch
        path: String,
    },

    /// Replay a transaction sequence and get execution traces
    ReplaySequence {
        id: u64,
        /// Raw JSON serialized sequence (same format as corpus files)
        #[serde(rename = "sequenceJson")]
        sequence_json: String,
    },
}

/// Campaign configuration for starting a new campaign
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignConfig {
    /// Test mode: "property", "assertion", "optimization", "exploration"
    #[serde(default = "default_test_mode")]
    pub test_mode: String,

    /// Number of workers
    #[serde(default = "default_workers")]
    pub workers: u8,

    /// Test limit (total calls)
    #[serde(default = "default_test_limit")]
    pub test_limit: usize,

    /// Sequence length
    #[serde(default = "default_seq_len")]
    pub seq_len: usize,

    /// Corpus directory
    pub corpus_dir: Option<String>,

    /// Random seed (optional)
    pub seed: Option<u64>,

    /// Timeout in seconds (optional)
    pub timeout: Option<u64>,

    /// Stop on first failure
    #[serde(default)]
    pub stop_on_fail: bool,
}

fn default_test_mode() -> String {
    "assertion".to_string()
}

fn default_workers() -> u8 {
    4
}

fn default_test_limit() -> usize {
    50000
}

fn default_seq_len() -> usize {
    100
}

/// Transaction request from UI
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxRequest {
    /// Function name or selector
    pub function: String,

    /// Arguments as strings (will be parsed based on ABI)
    pub args: Vec<String>,

    /// Sender address (optional, uses default if not specified)
    pub sender: Option<String>,

    /// ETH value (optional)
    pub value: Option<String>,

    /// Target contract (optional, uses main contract if not specified)
    pub target: Option<String>,
}

// ============================================================================
// Helper implementations
// ============================================================================

impl From<&evm::types::Tx> for TxPayload {
    fn from(tx: &evm::types::Tx) -> Self {
        let (function, args) = match &tx.call {
            evm::types::TxCall::SolCall { name, args } => {
                let arg_strs: Vec<String> = args.iter().map(|a| format!("{:?}", a)).collect();
                (name.clone(), arg_strs)
            }
            evm::types::TxCall::SolCreate(bytes) => {
                ("create".to_string(), vec![format!("0x{}", hex::encode(bytes))])
            }
            evm::types::TxCall::SolCalldata(bytes) => {
                ("raw".to_string(), vec![format!("0x{}", hex::encode(bytes))])
            }
            evm::types::TxCall::NoCall => ("delay".to_string(), vec![]),
        };

        TxPayload {
            function,
            args,
            sender: tx.src,
            target: tx.dst,
            value: tx.value.to_string(),
            delay_time: tx.delay.0,
            delay_blocks: tx.delay.1,
        }
    }
}

impl ContractSummary {
    /// Create from a CompiledContract (lightweight, no bytecode)
    pub fn from_compiled(
        contract: &evm::foundry::CompiledContract,
        address: Option<Address>,
    ) -> Self {
        let codehash = alloy_primitives::keccak256(&contract.deployed_bytecode);
        let function_count = contract.abi.functions().count();
        let has_tests = contract.abi.functions().any(|f| f.name.starts_with("echidna_"));

        ContractSummary {
            name: contract.name.clone(),
            qualified_name: contract.qualified_name.clone(),
            address,
            codehash,
            function_count,
            has_tests,
        }
    }
}

impl SourceFileSummary {
    /// Create from a SourceFile (lightweight, no content)
    pub fn from_source_file(file: &SourceFile) -> Self {
        SourceFileSummary {
            path: file.path.clone(),
            language: file.language.clone(),
            size: file.content.len(),
        }
    }
}

impl ContractInfo {
    /// Create from a CompiledContract
    pub fn from_compiled(
        contract: &evm::foundry::CompiledContract,
        address: Option<Address>,
    ) -> Self {
        let codehash = alloy_primitives::keccak256(&contract.deployed_bytecode);

        let functions: Vec<FunctionInfo> = contract
            .abi
            .functions()
            .map(|f| FunctionInfo {
                name: f.name.clone(),
                signature: f.signature(),
                selector: format!("0x{}", hex::encode(f.selector())),
                inputs: f
                    .inputs
                    .iter()
                    .map(|p| ParamInfo {
                        name: p.name.clone(),
                        ty: p.ty.to_string(),
                    })
                    .collect(),
                outputs: f
                    .outputs
                    .iter()
                    .map(|p| ParamInfo {
                        name: p.name.clone(),
                        ty: p.ty.to_string(),
                    })
                    .collect(),
                state_mutability: format!("{:?}", f.state_mutability),
            })
            .collect();

        ContractInfo {
            name: contract.name.clone(),
            qualified_name: contract.qualified_name.clone(),
            address,
            codehash,
            bytecode_hex: format!("0x{}", hex::encode(&contract.bytecode)),
            deployed_bytecode_hex: format!("0x{}", hex::encode(&contract.deployed_bytecode)),
            source_map: contract.source_map.clone(),
            functions,
        }
    }
}

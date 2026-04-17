/**
 * WebSocket protocol types for communication with the fuzzer backend.
 * These types mirror the Rust protocol types in web-core/src/protocol.rs
 */

// ============================================================================
// Server -> Client Messages
// ============================================================================

export type ServerMessage =
  | { type: 'init'; } & InitPayload
  | { type: 'stateUpdate'; } & StateUpdatePayload
  | { type: 'newCoverage'; } & NewCoverageEvent
  | { type: 'newCorpusEntry'; } & CorpusEntryPayload
  | { type: 'testStateChanged'; } & TestStatePayload
  | { type: 'campaignStateChanged'; } & CampaignStatePayload
  | { type: 'workerMessage'; workerId: number; message: string }
  | { type: 'commandResult'; id: number; success: boolean; message: string }
  | { type: 'contractDetails'; id: number; contract: ContractInfo | null }
  | { type: 'sourceFileContent'; id: number; file: SourceFile | null }
  | { type: 'replayResult'; id: number; success: boolean; traces: TxTraceResult[]; error: string | null }
  | { type: 'error'; message: string };

// Campaign state
export type CampaignState = 'idle' | 'running' | 'stopping' | 'finished';

export interface CampaignStatePayload {
  state: CampaignState;
  message?: string;
  result?: CampaignResult;
}

export interface CampaignResult {
  totalCalls: number;
  totalCoverage: number;
  testsPassed: number;
  testsFailed: number;
  corpusSize: number;
  durationSecs: number;
}

export interface InitPayload {
  contracts: ContractSummary[];
  totalContracts: number;
  config: ConfigSummary;
  sourceFiles: SourceFileSummary[];
  coverage: CoverageSnapshot;
  corpus: CorpusEntryPayload[];
  tests: TestInfo[];
  workers: WorkerInfo[];
  campaignState?: CampaignState;
  /** Source-level line coverage (LCOV-style, computed from PC coverage) */
  sourceLineCoverage: SourceLineCoverage[];
  /** PC to source mappings for each contract (for bytecode -> source navigation) */
  pcMappings: ContractPcMapping[];
}

/** Lightweight contract summary (no bytecode) for listing */
export interface ContractSummary {
  name: string;
  qualifiedName: string;
  address: string | null;
  codehash: string;
  functionCount: number;
  hasTests: boolean;
}

/** Lightweight source file summary (no content) */
export interface SourceFileSummary {
  path: string;
  language: string;
  size: number;
}

export interface ContractInfo {
  name: string;
  qualifiedName: string;
  address: string | null;
  codehash: string;
  bytecodeHex: string;
  deployedBytecodeHex: string;
  sourceMap: string | null;
  functions: FunctionInfo[];
}

export interface FunctionInfo {
  name: string;
  signature: string;
  selector: string;
  inputs: ParamInfo[];
  outputs: ParamInfo[];
  stateMutability: string;
}

export interface ParamInfo {
  name: string;
  type: string;
}

export interface SourceFile {
  path: string;
  content: string;
  language: string;
}

export interface ConfigSummary {
  testMode: string;
  workers: number;
  testLimit: number;
  seqLen: number;
  coverageMode: string;
  targetContracts: string[];
  senders: string[];
  srcFolder: string;
  testFolder: string;
}

export interface StateUpdatePayload {
  elapsedMs: number;
  totalCalls: number;
  totalSequences: number;
  totalGas: number;
  coverageDelta: CoverageDelta;
  workers: WorkerSnapshot[];
  revertHotspots: RevertHotspot[];
  corpusSize: number;
  campaignState?: CampaignState;
  /** Updated source-level line coverage (only sent when coverage has changed) */
  sourceLineCoverage?: SourceLineCoverage[];
}

export interface CoverageSnapshot {
  runtime: ContractCoverage[];
  init: ContractCoverage[];
  totalInstructions: number;
  totalContracts: number;
}

export interface ContractCoverage {
  codehash: string;
  coveredPcs: number[];
}

export interface CoverageDelta {
  newRuntime: ContractCoverage[];
  newInit: ContractCoverage[];
  newInstructions: number;
}

export interface RevertHotspot {
  codehash: string;
  pc: number;
  count: number;
  functionName: string | null;
  sourceLocation: SourceLocation | null;
}

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
}

// ============================================================================
// Source-Level Coverage (LCOV-style)
// ============================================================================

/** Line coverage for a source file (like LCOV DA entries) */
export interface SourceLineCoverage {
  /** File path relative to project root */
  path: string;
  /** Per-line coverage data */
  lines: LineCoverage[];
}

/** Coverage data for a single line */
export interface LineCoverage {
  /** Line number (1-indexed) */
  line: number;
  /** Number of times this line was hit */
  hits: number;
}

// ============================================================================
// PC to Source Mapping (for bytecode -> source navigation)
// ============================================================================

/** PC to source location mapping for a contract */
export interface ContractPcMapping {
  /** Contract codehash as hex string */
  codehash: string;
  /** Map of PC -> source location (sparse - only significant PCs) */
  pcToSource: PcSourceEntry[];
}

/** Single PC to source mapping entry */
export interface PcSourceEntry {
  /** Program counter */
  pc: number;
  /** Source file path */
  file: string;
  /** Line number (1-indexed) */
  line: number;
  /** Column number (1-indexed) */
  column: number;
  /** Byte offset in source */
  offset: number;
  /** Length of the source range */
  length: number;
}

export interface WorkerSnapshot {
  id: number;
  calls: number;
  sequences: number;
  gas: number;
  isInteractive: boolean;
  status: WorkerStatus;
}

export type WorkerStatus =
  | { type: 'fuzzing' }
  | { type: 'shrinking' }
  | { type: 'idle' }
  | { type: 'executingCommand'; command: string };

export interface WorkerInfo {
  id: number;
  isInteractive: boolean;
}

export interface NewCoverageEvent {
  workerId: number;
  newInstructions: number;
  totalInstructions: number;
  totalContracts: number;
  corpusSize: number;
}

export interface CorpusEntryPayload {
  id: string;
  priority: number;
  sequence: TxPayload[];
  /** Raw JSON serialized sequence (for replay - matches corpus file format) */
  sequenceJson: string;
  coverageContribution: number;
}

export interface TxPayload {
  function: string;
  args: string[];
  sender: string;
  target: string;
  value: string;
  delayTime: number;
  delayBlocks: number;
}

/** Transaction trace result from replay */
export interface TxTraceResult {
  index: number;
  tx: TxPayload;
  success: boolean;
  result: string;
  gasUsed: number;
  callTrace: CallTraceEntry[];
  events: EventEntry[];
  storageChanges: StorageChange[];
}

/** Single call in the execution trace */
export interface CallTraceEntry {
  depth: number;
  callType: string;
  from: string;
  to: string;
  function: string | null;
  input: string;
  output: string;
  gasUsed: number;
  success: boolean;
  revertReason: string | null;
}

/** Event emitted during execution */
export interface EventEntry {
  address: string;
  name: string | null;
  topics: string[];
  data: string;
}

/** Storage slot change */
export interface StorageChange {
  address: string;
  contractName: string | null;
  slot: string;
  previous: string;
  current: string;
}

export interface TestInfo {
  id: string;
  testType: string;
  state: string;
  value: string | null;
  failureSequence: TxPayload[] | null;
  /** Raw JSON serialized failure sequence (for replay - matches corpus file format) */
  failureSequenceJson: string | null;
  workerId: number | null;
}

export interface TestStatePayload {
  id: string;
  state: string;
  value: string | null;
  failureSequence: TxPayload[] | null;
  /** Raw JSON serialized failure sequence (for replay - matches corpus file format) */
  failureSequenceJson: string | null;
}

// ============================================================================
// Client -> Server Messages
// ============================================================================

export type ClientMessage =
  | { type: 'injectDictionary'; id: number; values: string[]; broadcast: boolean }
  | { type: 'injectSequence'; id: number; sequence: TxRequest[] }
  | { type: 'clampArgument'; id: number; function: string; paramIdx: number; value: string }
  | { type: 'unclampArgument'; id: number; function: string; paramIdx: number }
  | { type: 'clearAllClamps'; id: number }
  | { type: 'solveBranch'; id: number; codehash: string; pc: number }
  | { type: 'setTargetFunctions'; id: number; functions: string[] }
  | { type: 'llmQuery'; id: number; prompt: string; context: LlmContext }
  | { type: 'injectFuzzTransactions'; id: number; template: string; priority: number }
  | { type: 'clearFuzzTemplates'; id: number }
  | { type: 'requestFullState'; id: number }
  | { type: 'ping'; id: number }
  | { type: 'getContractDetails'; id: number; contractName: string }
  | { type: 'getSourceFile'; id: number; path: string }
  | { type: 'replaySequence'; id: number; sequenceJson: string };

// Campaign configuration for starting a new campaign
export interface CampaignConfig {
  testMode: string;
  workers: number;
  testLimit: number;
  seqLen: number;
  corpusDir?: string;
  seed?: number;
  timeout?: number;
  stopOnFail: boolean;
  concolic: boolean;
}

export interface TxRequest {
  function: string;
  args: string[];
  sender?: string;
  value?: string;
  target?: string;
}

export interface LlmContext {
  includeCoverage: boolean;
  includeCorpus: boolean;
  includeStruggling: boolean;
  customContext?: string;
}

// ============================================================================
// Helper types
// ============================================================================

export type TestState = 'open' | 'passed' | 'solved' | 'unsolvable' | 'shrinking' | 'failed';

export type TestType = 'property' | 'assertion' | 'optimization' | 'call' | 'exploration';

export interface ParsedSourceMap {
  entries: SourceMapEntry[];
}

export interface SourceMapEntry {
  start: number;
  length: number;
  fileIndex: number;
  jump: 'i' | 'o' | '-';
  modifierDepth: number;
}

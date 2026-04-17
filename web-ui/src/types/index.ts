// Re-export all types
export * from './protocol';

// Re-export transaction serialization utilities
export * from '../lib/txSerializer';

// Additional UI-specific types

/**
 * Branch target for concolic solving
 * This is the key type that connects the frontend CFG view to the backend solver.
 * The codehash + pc uniquely identifies a branch across contract deployments.
 */
export interface BranchTarget {
  /** Contract codehash (keccak256 of deployed bytecode) - hex string */
  codehash: string;
  /** Program counter of the JUMPI instruction */
  pc: number;
  /** Whether we want to take the true branch (jump) or false branch (fall through) */
  takeBranch: boolean;
}

/**
 * Branch information extracted from CFG
 */
export interface BranchInfo {
  /** PC of the JUMPI instruction */
  pc: number;
  /** Target PC if branch is taken (from PUSH before JUMPI) */
  targetPc: number | null;
  /** Fall-through PC if branch is not taken */
  fallthroughPc: number;
  /** Whether true branch (jump) has been covered */
  trueCovered: boolean;
  /** Whether false branch (fallthrough) has been covered */
  falseCovered: boolean;
}

/**
 * CFG node for react-flow visualization
 */
export interface CFGBlock {
  startPc: number;
  endPc: number;
  instructions: DisassembledInstruction[];
  isCovered: boolean;
  isRevertHotspot: boolean;
  revertCount: number;
  depth: number;
  /** Branch at end of block (if block ends with JUMPI) */
  branch?: BranchInfo;
  /** Block termination type */
  terminationType?: 'jump' | 'jumpi' | 'terminate' | 'fall';
  /** For terminate blocks: true = STOP/RETURN, false = REVERT/INVALID */
  isSuccess?: boolean;
  /** Function selector if this is a function entry block */
  functionSelector?: string;
}

export interface DisassembledInstruction {
  pc: number;
  opcode: string;
  args: string;
  isCovered: boolean;
  /** For JUMPI: the target PC (parsed from preceding PUSH) */
  jumpTarget?: number;
}

export interface CFGEdge {
  from: number;
  to: number;
  type: 'jump' | 'jumpi-true' | 'jumpi-false' | 'fall';
  /** Whether this edge has been taken (for coverage visualization) */
  covered?: boolean;
}

export interface CFG {
  blocks: CFGBlock[];
  edges: CFGEdge[];
}

/**
 * Line coverage mapping for source view (UI-specific)
 * Note: Different from protocol.LineCoverage which is simpler (line, hits)
 */
export interface LineCoverageInfo {
  line: number;
  isCovered: boolean;
  isPartial: boolean;
  hitCount: number;
  pcs: number[];
}

/**
 * Panel layout configuration
 */
export interface LayoutConfig {
  leftPanelSize: number;
  rightPanelSize: number;
  topPanelSize: number;
  bottomPanelSize: number;
}

/**
 * User preferences
 */
export interface UserPreferences {
  theme: 'dark' | 'light';
  fontSize: number;
  showLineNumbers: boolean;
  autoRefresh: boolean;
  refreshInterval: number;
}

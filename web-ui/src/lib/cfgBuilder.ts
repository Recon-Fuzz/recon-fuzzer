/**
 * CFG builder using evmole's WASM-based analysis
 *
 * Evmole is a Rust library compiled to WebAssembly for fast EVM bytecode analysis.
 * It provides control flow graph extraction, function selector detection, and disassembly.
 *
 * WASM Loading Strategy:
 * - Use evmole/no_tla (no top-level await) for manual initialization control
 * - Fetch WASM from /public/wasm/ with streaming compilation for best performance
 * - Fallback to pure JS implementation if WASM fails to load
 */

import type { CFG, CFGBlock, CFGEdge } from '@/types';

// ============================================================================
// Evmole Types (from WASM module)
// ============================================================================

interface EvmoleBlock {
  start: number;
  end: number;
  type: 'Terminate' | 'Jump' | 'Jumpi' | 'DynamicJump' | 'DynamicJumpi';
  data: {
    success?: boolean;
    to?: number | { path: number[]; to?: number };
    true_to?: number | { path: number[]; to?: number };
    false_to?: number;
  };
}

interface EvmoleContract {
  functions?: Array<{
    selector: string;
    bytecodeOffset: number;
    arguments?: string;
    stateMutability?: string;
  }>;
  disassembled?: [number, string][];
  controlFlowGraph?: { blocks: EvmoleBlock[] };
}

interface EvmoleAPI {
  contractInfo: (code: string, options: {
    selectors?: boolean;
    arguments?: boolean;
    stateMutability?: boolean;
    storage?: boolean;
    disassemble?: boolean;
    basicBlocks?: boolean;
    controlFlowGraph?: boolean;
  }) => EvmoleContract;
}

// ============================================================================
// WASM Module Loader
// ============================================================================

let evmole: EvmoleAPI | null = null;
let loadPromise: Promise<EvmoleAPI | null> | null = null;
let loadAttempted = false;

/**
 * Initialize evmole WASM module
 * Uses streaming compilation for optimal performance
 */
export async function initEvmole(): Promise<boolean> {
  if (evmole) return true;
  if (loadPromise) {
    const result = await loadPromise;
    return result !== null;
  }
  if (loadAttempted) return false;

  // Only load on client side
  if (typeof window === 'undefined') {
    console.log('[evmole] Skipping WASM load on server');
    return false;
  }

  loadAttempted = true;
  loadPromise = loadEvmoleWasm();
  const result = await loadPromise;
  return result !== null;
}

async function loadEvmoleWasm(): Promise<EvmoleAPI | null> {
  const startTime = performance.now();

  try {
    console.log('[evmole] Loading WASM module...');

    // Import the no_tla version which exports init function
    const evmoleModule = await import('evmole/no_tla');

    // Initialize with WASM from public folder
    // The init function accepts a URL string and uses fetch + streaming compilation
    const wasmPath = '/wasm/evmole_bg.wasm';

    // Call the default export (init function) with the WASM URL
    // This uses WebAssembly.instantiateStreaming internally for best performance
    await evmoleModule.default({ module_or_path: wasmPath });

    evmole = evmoleModule as EvmoleAPI;

    const loadTime = (performance.now() - startTime).toFixed(1);
    console.log(`[evmole] WASM loaded successfully in ${loadTime}ms`);

    return evmole;
  } catch (error) {
    console.error('[evmole] Failed to load WASM:', error);
    console.log('[evmole] Will use fallback JS implementation');
    return null;
  }
}

/**
 * Get the evmole module synchronously (returns null if not loaded)
 */
function getEvmole(): EvmoleAPI | null {
  return evmole;
}

/**
 * Check if evmole WASM is loaded and ready
 */
export function isEvmoleReady(): boolean {
  return evmole !== null;
}

// ============================================================================
// CFG Building
// ============================================================================

/**
 * Build CFG from bytecode using evmole's native WASM analysis
 */
export function buildCFGFromBytecode(bytecodeHex: string): CFG {
  const api = getEvmole();

  if (!api) {
    console.log('[CFG] Evmole not loaded, using fallback');
    return buildCFGFallback(bytecodeHex);
  }

  try {
    const code = bytecodeHex.startsWith('0x') ? bytecodeHex : `0x${bytecodeHex}`;
    const startTime = performance.now();

    const result = api.contractInfo(code, {
      controlFlowGraph: true,
      disassemble: true,
      selectors: true,
    });

    const analysisTime = (performance.now() - startTime).toFixed(1);

    if (!result.controlFlowGraph?.blocks) {
      console.warn('[CFG] Evmole returned no blocks');
      return { blocks: [], edges: [] };
    }

    // Convert evmole output to our CFG format
    const { blocks, edges } = convertEvmoleCFG(result);

    console.log(`[CFG] Built ${blocks.length} blocks, ${edges.length} edges in ${analysisTime}ms (WASM)`);
    return { blocks, edges };

  } catch (error) {
    console.error('[CFG] Evmole analysis failed:', error);
    return buildCFGFallback(bytecodeHex);
  }
}

/**
 * Build CFG asynchronously (loads WASM if needed)
 */
export async function buildCFGFromBytecodeAsync(bytecodeHex: string): Promise<CFG> {
  await initEvmole();
  return buildCFGFromBytecode(bytecodeHex);
}

/**
 * Helper to extract value from evmole block (handles Map objects from WASM)
 */
function getBlockValue<T>(block: unknown, key: string): T | undefined {
  if (block instanceof Map) {
    return block.get(key) as T | undefined;
  }
  return (block as Record<string, T>)[key];
}

/**
 * Helper to extract data value from evmole block
 */
function getBlockDataValue<T>(block: unknown, key: string): T | undefined {
  const data = getBlockValue<unknown>(block, 'data');
  if (data instanceof Map) {
    return data.get(key) as T | undefined;
  }
  if (data && typeof data === 'object') {
    return (data as Record<string, T>)[key];
  }
  return undefined;
}

/**
 * Convert evmole output to our CFG format
 * Note: WASM returns Map objects, not plain JS objects
 */
function convertEvmoleCFG(result: EvmoleContract): { blocks: CFGBlock[]; edges: CFGEdge[] } {
  const blocks: CFGBlock[] = [];
  const edges: CFGEdge[] = [];

  // Build disassembly lookup map
  const disasmMap = new Map<number, string>();
  if (result.disassembled) {
    for (const [pc, inst] of result.disassembled) {
      disasmMap.set(pc, inst);
    }
  }

  // Process each evmole block (may be Map objects from WASM)
  for (const rawBlock of result.controlFlowGraph!.blocks) {
    const evStart = getBlockValue<number>(rawBlock, 'start');
    const evEnd = getBlockValue<number>(rawBlock, 'end');
    const evType = getBlockValue<string>(rawBlock, 'type');

    // Skip invalid blocks
    if (evStart === undefined || evEnd === undefined) {
      console.warn('[CFG] Skipping block with undefined start/end');
      continue;
    }

    // Extract instructions for this block
    const instructions: CFGBlock['instructions'] = [];

    if (result.disassembled) {
      for (const [pc, inst] of result.disassembled) {
        if (pc >= evStart && pc <= evEnd) {
          const parts = inst.split(' ');
          instructions.push({
            pc,
            opcode: parts[0],
            args: parts.slice(1).join(' '),
            isCovered: false,
          });
        }
      }
    }

    // Fallback if no disassembly
    if (instructions.length === 0) {
      instructions.push({
        pc: evStart,
        opcode: evType || 'UNKNOWN',
        args: '',
        isCovered: false,
      });
    }

    // Determine termination type
    let terminationType: CFGBlock['terminationType'] = 'fall';
    let isSuccess = true;

    switch (evType) {
      case 'Terminate':
        terminationType = 'terminate';
        isSuccess = getBlockDataValue<boolean>(rawBlock, 'success') ?? false;
        break;
      case 'Jump':
      case 'DynamicJump':
        terminationType = 'jump';
        break;
      case 'Jumpi':
      case 'DynamicJumpi':
        terminationType = 'jumpi';
        break;
    }

    const block: CFGBlock = {
      startPc: evStart,
      endPc: evEnd,
      instructions,
      isCovered: false,
      isRevertHotspot: false,
      revertCount: 0,
      depth: 0,
      terminationType,
      isSuccess,
    };

    // Add branch info for conditional jumps
    if (evType === 'Jumpi' || evType === 'DynamicJumpi') {
      const trueToRaw = getBlockDataValue<number | Map<string, unknown>>(rawBlock, 'true_to');
      const falseTo = getBlockDataValue<number>(rawBlock, 'false_to');

      const trueTo = typeof trueToRaw === 'number'
        ? trueToRaw
        : (trueToRaw instanceof Map ? trueToRaw.get('to') as number : undefined);

      if (trueTo !== undefined || falseTo !== undefined) {
        block.branch = {
          pc: evEnd,
          targetPc: trueTo ?? null,
          fallthroughPc: falseTo ?? evEnd + 1,
          trueCovered: false,
          falseCovered: false,
        };
      }
    }

    blocks.push(block);

    // Create edges
    createEdgesFromRawBlock(rawBlock, evStart, evType, edges);
  }

  // Calculate depths via BFS
  calculateBlockDepths(blocks, edges);

  // Map function selectors to blocks
  if (result.functions?.length) {
    mapFunctionSelectors(blocks, result.functions);
  }

  return { blocks, edges };
}

/**
 * Create edges for a block based on its type (handles Map objects from WASM)
 */
function createEdgesFromRawBlock(
  rawBlock: unknown,
  startPc: number,
  blockType: string | undefined,
  edges: CFGEdge[]
): void {
  switch (blockType) {
    case 'Jump': {
      const toRaw = getBlockDataValue<number | Map<string, unknown>>(rawBlock, 'to');
      const to = typeof toRaw === 'number' ? toRaw : (toRaw instanceof Map ? toRaw.get('to') as number : undefined);
      if (to !== undefined) {
        edges.push({ from: startPc, to, type: 'jump' });
      }
      break;
    }
    case 'DynamicJump': {
      const dynTo = getBlockDataValue<Map<string, unknown>>(rawBlock, 'to');
      const to = dynTo instanceof Map ? dynTo.get('to') as number : undefined;
      if (to !== undefined) {
        edges.push({ from: startPc, to, type: 'jump' });
      }
      break;
    }
    case 'Jumpi': {
      const trueTo = getBlockDataValue<number>(rawBlock, 'true_to');
      const falseTo = getBlockDataValue<number>(rawBlock, 'false_to');
      if (trueTo !== undefined) {
        edges.push({ from: startPc, to: trueTo, type: 'jumpi-true' });
      }
      if (falseTo !== undefined) {
        edges.push({ from: startPc, to: falseTo, type: 'jumpi-false' });
      }
      break;
    }
    case 'DynamicJumpi': {
      const dynTrueTo = getBlockDataValue<Map<string, unknown>>(rawBlock, 'true_to');
      const trueTo = dynTrueTo instanceof Map ? dynTrueTo.get('to') as number : undefined;
      const falseTo = getBlockDataValue<number>(rawBlock, 'false_to');
      if (trueTo !== undefined) {
        edges.push({ from: startPc, to: trueTo, type: 'jumpi-true' });
      }
      if (falseTo !== undefined) {
        edges.push({ from: startPc, to: falseTo, type: 'jumpi-false' });
      }
      break;
    }
    // Terminate blocks have no outgoing edges
  }
}

/**
 * Calculate block depths using BFS from entry point
 */
function calculateBlockDepths(blocks: CFGBlock[], edges: CFGEdge[]): void {
  const blockByStart = new Map<number, CFGBlock>();
  for (const block of blocks) {
    blockByStart.set(block.startPc, block);
  }

  const visited = new Set<number>();
  const queue: { pc: number; depth: number }[] = [];

  const entryPc = blocks[0]?.startPc ?? 0;
  queue.push({ pc: entryPc, depth: 0 });

  while (queue.length > 0) {
    const { pc, depth } = queue.shift()!;
    if (visited.has(pc)) continue;
    visited.add(pc);

    const block = blockByStart.get(pc);
    if (block) {
      block.depth = depth;

      for (const edge of edges) {
        if (edge.from === pc && !visited.has(edge.to)) {
          queue.push({ pc: edge.to, depth: depth + 1 });
        }
      }
    }
  }
}

/**
 * Map function selectors to their entry blocks
 */
function mapFunctionSelectors(
  blocks: CFGBlock[],
  functions: Array<{ selector: string; bytecodeOffset: number }>
): void {
  const blockByStart = new Map<number, CFGBlock>();
  for (const block of blocks) {
    blockByStart.set(block.startPc, block);
  }

  for (const func of functions) {
    const offset = func.bytecodeOffset;

    // Try exact match first
    let targetBlock = blockByStart.get(offset);

    // If no exact match, find containing block
    if (!targetBlock) {
      for (const block of blocks) {
        if (offset >= block.startPc && offset <= block.endPc) {
          targetBlock = block;
          break;
        }
      }
    }

    if (targetBlock) {
      targetBlock.functionSelector = func.selector;
    }
  }
}

// ============================================================================
// Coverage Functions
// ============================================================================

/**
 * Get important PCs for coverage tracking
 *
 * Coverage model tracks only key PCs to minimize data:
 * - Block entry PCs (JUMPDEST or first instruction)
 * - Block terminator PCs (JUMP/JUMPI/RETURN/REVERT/etc)
 * - Branch target PCs for determining which branches were taken
 */
export function getImportantPCs(cfg: CFG): Set<number> {
  const important = new Set<number>();

  for (const block of cfg.blocks) {
    important.add(block.startPc);
    important.add(block.endPc);

    if (block.branch) {
      if (block.branch.targetPc !== null) {
        important.add(block.branch.targetPc);
      }
      if (block.branch.fallthroughPc !== null) {
        important.add(block.branch.fallthroughPc);
      }
    }
  }

  return important;
}

/**
 * Apply coverage data to CFG
 *
 * Coverage logic:
 * - Block covered if entry OR exit PC is in covered set
 * - True branch covered if target PC is covered
 * - False branch covered if fallthrough PC is covered
 */
export function applyCoverage(cfg: CFG, coveredPcs: Set<number>): void {
  for (const block of cfg.blocks) {
    block.isCovered = coveredPcs.has(block.endPc) || coveredPcs.has(block.startPc);

    for (const inst of block.instructions) {
      inst.isCovered = coveredPcs.has(inst.pc) ||
        (block.isCovered && inst.pc <= block.endPc);
    }

    if (block.branch) {
      if (block.branch.targetPc !== null) {
        block.branch.trueCovered = coveredPcs.has(block.branch.targetPc);
      }
      if (block.branch.fallthroughPc !== null) {
        block.branch.falseCovered = coveredPcs.has(block.branch.fallthroughPc);
      }
    }
  }
}

/**
 * Check if an edge is covered
 */
export function isEdgeCovered(edge: CFGEdge, coveredPcs: Set<number>): boolean {
  return coveredPcs.has(edge.to);
}

// ============================================================================
// Fallback JS Implementation
// ============================================================================

function buildCFGFallback(bytecodeHex: string): CFG {
  const bytecode = hexToBytes(bytecodeHex);
  if (bytecode.length === 0) return { blocks: [], edges: [] };

  const startTime = performance.now();

  // Disassemble
  const instructions: CFGBlock['instructions'] = [];
  let pc = 0;

  while (pc < bytecode.length) {
    const opcode = bytecode[pc];
    const info = OPCODES[opcode];

    if (!info) {
      instructions.push({ pc, opcode: `0x${opcode.toString(16).padStart(2, '0')}`, args: '', isCovered: false });
      pc++;
      continue;
    }

    let args = '';
    const pushBytes = info.push ?? 0;
    if (pushBytes > 0 && pc + pushBytes < bytecode.length) {
      const pushData = bytecode.slice(pc + 1, pc + 1 + pushBytes);
      args = '0x' + Array.from(pushData).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    instructions.push({ pc, opcode: info.name, args, isCovered: false });
    pc += 1 + pushBytes;
  }

  // Find block boundaries
  const terminators = new Set(['JUMP', 'JUMPI', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT']);
  const blockStarts = new Set<number>([0]);

  for (let i = 0; i < instructions.length; i++) {
    const inst = instructions[i];
    if (terminators.has(inst.opcode) && i + 1 < instructions.length) {
      blockStarts.add(instructions[i + 1].pc);
    }
    if (inst.opcode === 'JUMPDEST') {
      blockStarts.add(inst.pc);
    }
  }

  // Create blocks
  const sortedStarts = Array.from(blockStarts).sort((a, b) => a - b);
  const blocks: CFGBlock[] = [];

  for (let i = 0; i < sortedStarts.length; i++) {
    const startPc = sortedStarts[i];
    const nextStart = sortedStarts[i + 1] ?? Infinity;
    const blockInsts = instructions.filter(inst => inst.pc >= startPc && inst.pc < nextStart);

    if (blockInsts.length === 0) continue;

    const lastInst = blockInsts[blockInsts.length - 1];

    blocks.push({
      startPc,
      endPc: lastInst.pc,
      instructions: blockInsts,
      isCovered: false,
      isRevertHotspot: false,
      revertCount: 0,
      depth: 0,
    });
  }

  // Create edges
  const edges: CFGEdge[] = [];
  const jumpDests = new Set(instructions.filter(i => i.opcode === 'JUMPDEST').map(i => i.pc));

  for (const block of blocks) {
    const lastInst = block.instructions[block.instructions.length - 1];
    const prevInst = block.instructions[block.instructions.length - 2];

    if (lastInst.opcode === 'JUMP' && prevInst?.args) {
      const target = parseInt(prevInst.args, 16);
      if (jumpDests.has(target)) {
        edges.push({ from: block.startPc, to: target, type: 'jump' });
      }
    } else if (lastInst.opcode === 'JUMPI' && prevInst?.args) {
      const target = parseInt(prevInst.args, 16);
      if (jumpDests.has(target)) {
        edges.push({ from: block.startPc, to: target, type: 'jumpi-true' });
      }
      const nextStart = sortedStarts[sortedStarts.indexOf(block.startPc) + 1];
      if (nextStart !== undefined) {
        edges.push({ from: block.startPc, to: nextStart, type: 'jumpi-false' });
      }
    } else if (!terminators.has(lastInst.opcode)) {
      const nextStart = sortedStarts[sortedStarts.indexOf(block.startPc) + 1];
      if (nextStart !== undefined) {
        edges.push({ from: block.startPc, to: nextStart, type: 'fall' });
      }
    }
  }

  calculateBlockDepths(blocks, edges);

  const analysisTime = (performance.now() - startTime).toFixed(1);
  console.log(`[CFG] Built ${blocks.length} blocks, ${edges.length} edges in ${analysisTime}ms (JS fallback)`);

  return { blocks, edges };
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Opcode definitions for fallback
const OPCODES: Record<number, { name: string; push?: number }> = {
  0x00: { name: 'STOP' }, 0x01: { name: 'ADD' }, 0x02: { name: 'MUL' }, 0x03: { name: 'SUB' },
  0x04: { name: 'DIV' }, 0x05: { name: 'SDIV' }, 0x06: { name: 'MOD' }, 0x07: { name: 'SMOD' },
  0x08: { name: 'ADDMOD' }, 0x09: { name: 'MULMOD' }, 0x0a: { name: 'EXP' }, 0x0b: { name: 'SIGNEXTEND' },
  0x10: { name: 'LT' }, 0x11: { name: 'GT' }, 0x12: { name: 'SLT' }, 0x13: { name: 'SGT' },
  0x14: { name: 'EQ' }, 0x15: { name: 'ISZERO' }, 0x16: { name: 'AND' }, 0x17: { name: 'OR' },
  0x18: { name: 'XOR' }, 0x19: { name: 'NOT' }, 0x1a: { name: 'BYTE' }, 0x1b: { name: 'SHL' },
  0x1c: { name: 'SHR' }, 0x1d: { name: 'SAR' }, 0x20: { name: 'SHA3' },
  0x30: { name: 'ADDRESS' }, 0x31: { name: 'BALANCE' }, 0x32: { name: 'ORIGIN' }, 0x33: { name: 'CALLER' },
  0x34: { name: 'CALLVALUE' }, 0x35: { name: 'CALLDATALOAD' }, 0x36: { name: 'CALLDATASIZE' },
  0x37: { name: 'CALLDATACOPY' }, 0x38: { name: 'CODESIZE' }, 0x39: { name: 'CODECOPY' },
  0x3a: { name: 'GASPRICE' }, 0x3b: { name: 'EXTCODESIZE' }, 0x3c: { name: 'EXTCODECOPY' },
  0x3d: { name: 'RETURNDATASIZE' }, 0x3e: { name: 'RETURNDATACOPY' }, 0x3f: { name: 'EXTCODEHASH' },
  0x40: { name: 'BLOCKHASH' }, 0x41: { name: 'COINBASE' }, 0x42: { name: 'TIMESTAMP' },
  0x43: { name: 'NUMBER' }, 0x44: { name: 'PREVRANDAO' }, 0x45: { name: 'GASLIMIT' },
  0x46: { name: 'CHAINID' }, 0x47: { name: 'SELFBALANCE' }, 0x48: { name: 'BASEFEE' },
  0x50: { name: 'POP' }, 0x51: { name: 'MLOAD' }, 0x52: { name: 'MSTORE' }, 0x53: { name: 'MSTORE8' },
  0x54: { name: 'SLOAD' }, 0x55: { name: 'SSTORE' }, 0x56: { name: 'JUMP' }, 0x57: { name: 'JUMPI' },
  0x58: { name: 'PC' }, 0x59: { name: 'MSIZE' }, 0x5a: { name: 'GAS' }, 0x5b: { name: 'JUMPDEST' },
  0x5f: { name: 'PUSH0', push: 0 },
  0xf0: { name: 'CREATE' }, 0xf1: { name: 'CALL' }, 0xf2: { name: 'CALLCODE' }, 0xf3: { name: 'RETURN' },
  0xf4: { name: 'DELEGATECALL' }, 0xf5: { name: 'CREATE2' }, 0xfa: { name: 'STATICCALL' },
  0xfd: { name: 'REVERT' }, 0xfe: { name: 'INVALID' }, 0xff: { name: 'SELFDESTRUCT' },
};

// PUSH1-PUSH32
for (let i = 1; i <= 32; i++) {
  OPCODES[0x5f + i] = { name: `PUSH${i}`, push: i };
}
// DUP1-DUP16
for (let i = 0; i < 16; i++) {
  OPCODES[0x80 + i] = { name: `DUP${i + 1}` };
}
// SWAP1-SWAP16
for (let i = 0; i < 16; i++) {
  OPCODES[0x90 + i] = { name: `SWAP${i + 1}` };
}
// LOG0-LOG4
for (let i = 0; i <= 4; i++) {
  OPCODES[0xa0 + i] = { name: `LOG${i}` };
}

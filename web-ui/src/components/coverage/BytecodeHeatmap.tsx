'use client';

import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { useContractDetails } from '@/hooks/useContractDetails';
import { cn } from '@/lib/utils';

// Instruction categories for coloring
type InstructionCategory = 'jump' | 'jumpi' | 'call' | 'return' | 'revert' | 'storage' | 'other';

interface BytecodeBlock {
  pc: number;
  opcode: string;
  category: InstructionCategory;
}

// Categorize opcodes
function categorizeOpcode(opcode: string): InstructionCategory {
  if (opcode === 'JUMP') return 'jump';
  if (opcode === 'JUMPI') return 'jumpi';
  if (opcode.startsWith('CALL') || opcode === 'DELEGATECALL' || opcode === 'STATICCALL' || opcode === 'CREATE' || opcode === 'CREATE2') return 'call';
  if (opcode === 'RETURN' || opcode === 'STOP') return 'return';
  if (opcode === 'REVERT' || opcode === 'INVALID' || opcode === 'SELFDESTRUCT') return 'revert';
  if (opcode === 'SLOAD' || opcode === 'SSTORE') return 'storage';
  return 'other';
}

// Colors for categories (uncovered)
const UNCOVERED_COLORS: Record<InstructionCategory, string> = {
  jump: '#7c2d12',    // orange-900
  jumpi: '#713f12',   // yellow-900
  call: '#1e3a5f',    // blue-900
  return: '#14532d',  // green-900
  revert: '#7f1d1d',  // red-900
  storage: '#581c87', // purple-900
  other: '#27272a',   // zinc-800
};

// Colors for categories (covered)
const COVERED_COLORS: Record<InstructionCategory, string> = {
  jump: '#f97316',    // orange-500
  jumpi: '#eab308',   // yellow-500
  call: '#3b82f6',    // blue-500
  return: '#22c55e',  // green-500
  revert: '#ef4444',  // red-500
  storage: '#a855f7', // purple-500
  other: '#22c55e',   // green-500
};

const HOTSPOT_COLOR = '#ef4444';  // red-500
const HOVER_RING_COLOR = '#ffffff';
const SELECTED_RING_COLOR = '#3b82f6';

// Simple disassembler
function disassembleBytecode(bytecodeHex: string): BytecodeBlock[] {
  const bytecode = hexToBytes(bytecodeHex);
  const blocks: BytecodeBlock[] = [];
  let pc = 0;

  while (pc < bytecode.length) {
    const opcode = bytecode[pc];
    const info = OPCODES[opcode];
    const opcodeName = info?.name ?? `0x${opcode.toString(16).padStart(2, '0')}`;
    const pushBytes = info?.push ?? 0;

    blocks.push({
      pc,
      opcode: opcodeName,
      category: categorizeOpcode(opcodeName),
    });

    pc += 1 + pushBytes;
  }

  return blocks;
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Hook for coverage - simplified to use direct selector
function useCoverageForContract(codehash: string | undefined) {
  // Direct selector - will re-render when coverage changes
  const coveredPcs = useFuzzerStore((state) => {
    if (!codehash) return new Set<number>();
    return state.coverage.runtime.get(codehash) ?? new Set<number>();
  });

  // Track version for cache busting (coverage size changes)
  const version = coveredPcs.size;

  return { coveredPcs, version };
}

// Hook for hotspots - simplified to use direct selector
function useHotspotsForContract(codehash: string | undefined) {
  const hotspotPcs = useFuzzerStore((state) => {
    if (!codehash) return new Map<number, number>();
    const map = new Map<number, number>();
    for (const h of state.revertHotspots) {
      if (h.codehash === codehash) {
        map.set(h.pc, h.count);
      }
    }
    return map;
  });

  return hotspotPcs;
}

// Track branch coverage for JUMPIs
interface BranchInfo {
  pc: number;
  index: number;
  trueCovered: boolean;
  falseCovered: boolean;
}

// Hook for PC to source mapping - simplified to use direct selector
function usePcMappingForContract(codehash: string | undefined) {
  const pcMapping = useFuzzerStore((state) => {
    if (!codehash) return new Map<number, { file: string; line: number; column: number }>();
    return state.pcMappings.get(codehash) ?? new Map<number, { file: string; line: number; column: number }>();
  });

  return pcMapping;
}

interface BytecodeHeatmapProps {
  className?: string;
}

// Constants for canvas rendering
const CELL_SIZE = 4;       // Size of each cell in pixels
const CELL_GAP = 1;        // Gap between cells
const CELL_TOTAL = CELL_SIZE + CELL_GAP;

// Special marker for partially covered branches
const PARTIAL_BRANCH_COLOR = '#f59e0b'; // amber-500 - needs attention

function BytecodeHeatmap({ className }: BytecodeHeatmapProps) {
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const contracts = useFuzzerStore((s) => s.contracts);

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0 });
  const [cols, setCols] = useState(0);
  const animationRef = useRef<number | null>(null);
  const blinkPhaseRef = useRef(0);

  const contractSummary = useMemo(
    () => contracts.find((c) => c.name === selectedContract),
    [contracts, selectedContract]
  );

  const contract = useContractDetails(selectedContract);
  const { coveredPcs, version } = useCoverageForContract(contractSummary?.codehash);
  const hotspotPcs = useHotspotsForContract(contractSummary?.codehash);
  const pcMapping = usePcMappingForContract(contractSummary?.codehash);

  // Actions for navigation
  const selectSourceFile = useFuzzerStore((s) => s.selectSourceFile);
  const highlightLine = useFuzzerStore((s) => s.highlightLine);

  // Disassemble bytecode
  const instructions = useMemo(() => {
    if (!contract?.deployedBytecodeHex) return [];
    return disassembleBytecode(contract.deployedBytecodeHex);
  }, [contract?.deployedBytecodeHex]);

  // Calculate coverage stats
  const stats = useMemo(() => {
    const total = instructions.length;
    const covered = instructions.filter(i => coveredPcs.has(i.pc)).length;
    const hotspots = hotspotPcs.size;
    return { total, covered, hotspots };
  }, [instructions, coveredPcs, hotspotPcs]);

  // Find JUMPI instructions and track branch coverage
  // A branch is "partially covered" if the JUMPI is reached but not both targets
  // TODO: In future, this data can be sent to symbolic executor to solve uncovered branches
  const _branchInfo = useMemo(() => {
    const branches: BranchInfo[] = [];

    instructions.forEach((inst, i) => {
      if (inst.opcode === 'JUMPI') {
        const jumpiCovered = coveredPcs.has(inst.pc);
        if (!jumpiCovered) return; // Not reached yet

        // For now, we can't easily determine true/false targets without full analysis
        // But we can mark JUMPIs that are covered as "interesting" for the user
        // In a more complete implementation, we'd parse the PUSH before JUMPI
        branches.push({
          pc: inst.pc,
          index: i,
          trueCovered: false, // Would need deeper analysis
          falseCovered: false,
        });
      }
    });

    return branches;
  }, [instructions, coveredPcs]);

  // JUMPIs that are covered (reached) - these are potential targets for symbolic
  const reachedJumpis = useMemo(() => {
    return instructions
      .map((inst, i) => ({ inst, i }))
      .filter(({ inst }) => inst.opcode === 'JUMPI' && coveredPcs.has(inst.pc));
  }, [instructions, coveredPcs]);

  // Uncovered JUMPIs - not yet reached
  const uncoveredJumpis = useMemo(() => {
    return instructions
      .map((inst, i) => ({ inst, i }))
      .filter(({ inst }) => inst.opcode === 'JUMPI' && !coveredPcs.has(inst.pc));
  }, [instructions, coveredPcs]);

  // Calculate canvas size based on container
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const resizeObserver = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        const { width, height } = entry.contentRect;
        const numCols = Math.floor(width / CELL_TOTAL);
        const numRows = Math.ceil(instructions.length / numCols);
        const canvasHeight = Math.min(numRows * CELL_TOTAL, height);

        setCols(numCols);
        setCanvasSize({ width, height: canvasHeight });
      }
    });

    resizeObserver.observe(container);
    return () => resizeObserver.disconnect();
  }, [instructions.length]);

  // Draw the canvas
  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || instructions.length === 0 || cols === 0) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvasSize.width * dpr;
    canvas.height = canvasSize.height * dpr;
    ctx.scale(dpr, dpr);

    // Clear
    ctx.fillStyle = '#09090b';
    ctx.fillRect(0, 0, canvasSize.width, canvasSize.height);

    // Calculate blink opacity for hotspots
    const blinkOpacity = 0.5 + 0.5 * Math.sin(blinkPhaseRef.current);

    // Draw cells
    instructions.forEach((inst, i) => {
      const row = Math.floor(i / cols);
      const col = i % cols;
      const x = col * CELL_TOTAL;
      const y = row * CELL_TOTAL;

      const isCovered = coveredPcs.has(inst.pc);
      const isHotspot = hotspotPcs.has(inst.pc);
      const isHovered = hoveredIndex === i;
      const isSelected = selectedIndex === i;

      // Determine color
      let color: string;
      if (isHotspot) {
        // Blink effect for hotspots
        const r = parseInt(HOTSPOT_COLOR.slice(1, 3), 16);
        const g = parseInt(HOTSPOT_COLOR.slice(3, 5), 16);
        const b = parseInt(HOTSPOT_COLOR.slice(5, 7), 16);
        color = `rgba(${r}, ${g}, ${b}, ${blinkOpacity})`;
      } else if (isCovered) {
        color = COVERED_COLORS[inst.category];
      } else {
        color = UNCOVERED_COLORS[inst.category];
      }

      ctx.fillStyle = color;
      ctx.fillRect(x, y, CELL_SIZE, CELL_SIZE);

      // Draw hover/selection ring
      if (isHovered || isSelected) {
        ctx.strokeStyle = isSelected ? SELECTED_RING_COLOR : HOVER_RING_COLOR;
        ctx.lineWidth = 1;
        ctx.strokeRect(x - 0.5, y - 0.5, CELL_SIZE + 1, CELL_SIZE + 1);
      }
    });
  }, [instructions, coveredPcs, hotspotPcs, hoveredIndex, selectedIndex, canvasSize, cols]);

  // Animation loop for hotspot blinking
  useEffect(() => {
    if (hotspotPcs.size === 0) {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
        animationRef.current = null;
      }
      draw();
      return;
    }

    const animate = () => {
      blinkPhaseRef.current += 0.1;
      draw();
      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [hotspotPcs.size, draw]);

  // Redraw when data changes (without animation)
  useEffect(() => {
    if (hotspotPcs.size === 0) {
      draw();
    }
  }, [draw, version, hotspotPcs.size]);

  // Mouse handlers
  const getIndexFromEvent = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || cols === 0) return null;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const col = Math.floor(x / CELL_TOTAL);
    const row = Math.floor(y / CELL_TOTAL);
    const index = row * cols + col;

    if (index >= 0 && index < instructions.length) {
      return index;
    }
    return null;
  }, [cols, instructions.length]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const index = getIndexFromEvent(e);
    setHoveredIndex(index);
  }, [getIndexFromEvent]);

  const handleMouseLeave = useCallback(() => {
    setHoveredIndex(null);
  }, []);

  // Navigate to source when clicking on an instruction with source mapping
  const navigateToSource = useCallback((file: string, line: number) => {
    selectSourceFile(file);
    highlightLine(line);
  }, [selectSourceFile, highlightLine]);

  const handleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const index = getIndexFromEvent(e);
    if (index === null) return;

    setSelectedIndex(index === selectedIndex ? null : index);

    // Navigate to source if available
    const inst = instructions[index];
    if (inst) {
      const sourceLocation = pcMapping.get(inst.pc);
      if (sourceLocation) {
        navigateToSource(sourceLocation.file, sourceLocation.line);
      }
    }
  }, [getIndexFromEvent, selectedIndex, instructions, pcMapping, navigateToSource]);

  // Get hovered instruction info (including source location)
  const hoveredInfo = useMemo(() => {
    if (hoveredIndex === null) return null;
    const inst = instructions[hoveredIndex];
    if (!inst) return null;

    const sourceLocation = pcMapping.get(inst.pc);

    return {
      pc: inst.pc,
      opcode: inst.opcode,
      covered: coveredPcs.has(inst.pc),
      revertCount: hotspotPcs.get(inst.pc) ?? 0,
      sourceFile: sourceLocation?.file ?? null,
      sourceLine: sourceLocation?.line ?? null,
    };
  }, [hoveredIndex, instructions, coveredPcs, hotspotPcs, pcMapping]);

  if (!contract) {
    return (
      <div className={cn('flex items-center justify-center h-full text-sm text-zinc-500', className)}>
        Select a contract to view bytecode coverage
      </div>
    );
  }

  if (instructions.length === 0) {
    return (
      <div className={cn('flex items-center justify-center h-full text-sm text-zinc-500', className)}>
        No bytecode available
      </div>
    );
  }

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Stats bar */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 text-xs flex-shrink-0">
        <div className="flex items-center gap-4">
          <span className="text-zinc-400">{contract.name}</span>
          <span className="text-zinc-500">{instructions.length} instructions</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-zinc-500">
            {stats.covered}/{stats.total}
          </span>
          <span className={stats.covered > 0 ? 'text-green-400' : 'text-zinc-500'}>
            {stats.total > 0 ? ((stats.covered / stats.total) * 100).toFixed(1) : 0}%
          </span>
          {stats.hotspots > 0 && (
            <span className="text-red-400">
              {stats.hotspots} hotspots
            </span>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-zinc-800 text-[10px] flex-wrap flex-shrink-0">
        <span className="text-zinc-500">Legend:</span>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-green-500 rounded-[1px]" />
          <span className="text-zinc-400">Covered</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-zinc-700 rounded-[1px]" />
          <span className="text-zinc-400">Not covered</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-yellow-500 rounded-[1px]" />
          <span className="text-zinc-400">JUMPI</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-orange-500 rounded-[1px]" />
          <span className="text-zinc-400">JUMP</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-blue-500 rounded-[1px]" />
          <span className="text-zinc-400">CALL</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2.5 h-2.5 bg-red-500 rounded-[1px]" />
          <span className="text-zinc-400">Hotspot</span>
        </div>
      </div>

      {/* Canvas container */}
      <div ref={containerRef} className="flex-1 overflow-auto min-h-0">
        <canvas
          ref={canvasRef}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          onClick={handleClick}
          style={{
            width: canvasSize.width,
            height: canvasSize.height,
            cursor: 'crosshair',
          }}
        />
      </div>

      {/* Info footer - always visible */}
      <div className="px-3 py-2 border-t border-zinc-800 text-xs bg-zinc-900/50 flex-shrink-0">
        {hoveredInfo ? (
          <div className="flex items-center gap-4 flex-wrap">
            <span className="font-mono text-zinc-400">
              PC: 0x{hoveredInfo.pc.toString(16).padStart(4, '0')}
            </span>
            <span className={cn(
              'font-mono font-medium',
              hoveredInfo.opcode === 'JUMPI' && 'text-yellow-400',
              hoveredInfo.opcode === 'JUMP' && 'text-orange-400',
              hoveredInfo.opcode.startsWith('CALL') && 'text-blue-400',
              hoveredInfo.opcode === 'REVERT' && 'text-red-400',
              hoveredInfo.opcode === 'RETURN' && 'text-green-400',
            )}>
              {hoveredInfo.opcode}
            </span>
            <span className={hoveredInfo.covered ? 'text-green-400' : 'text-zinc-500'}>
              {hoveredInfo.covered ? 'Covered' : 'Not covered'}
            </span>
            {hoveredInfo.revertCount > 0 && (
              <span className="text-red-400">
                {hoveredInfo.revertCount.toLocaleString()} reverts
              </span>
            )}
            {hoveredInfo.sourceFile && hoveredInfo.sourceLine && (
              <span
                className="text-blue-400 hover:underline cursor-pointer"
                onClick={() => navigateToSource(hoveredInfo.sourceFile!, hoveredInfo.sourceLine!)}
              >
                {hoveredInfo.sourceFile.split('/').pop()}:{hoveredInfo.sourceLine}
              </span>
            )}
            {hoveredInfo.opcode === 'JUMPI' && hoveredInfo.covered && (
              <span className="text-amber-400">
                Branch (click to target)
              </span>
            )}
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4 text-zinc-500">
              <span>Branches:</span>
              <span className="text-yellow-400">
                {reachedJumpis.length} reached
              </span>
              <span className="text-zinc-600">
                {uncoveredJumpis.length} unreached
              </span>
            </div>
            {reachedJumpis.length > 0 && (
              <span className="text-zinc-600 text-[10px]">
                Hover over yellow squares to explore branches
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Opcode definitions
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

export default memo(BytecodeHeatmap);

'use client';

import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import { cn } from '@/lib/utils';
import type { CFGBlock, DisassembledInstruction } from '@/types';

export interface CFGNodeData extends Record<string, unknown> {
  block: CFGBlock;
  isCovered: boolean;
  hotspotCount: number;
  isHighlighted: boolean;
  coveredPcs: Set<number>;
  isEntryPoint?: boolean;
  onPcClick: (pc: number) => void;
}

// Determine block type based on terminating instruction
type BlockType = 'revert' | 'return' | 'jump' | 'jumpi' | 'normal';

function getBlockType(block: CFGBlock): BlockType {
  if (block.terminationType === 'terminate') {
    return block.isSuccess ? 'return' : 'revert';
  }
  if (block.terminationType === 'jumpi') return 'jumpi';
  if (block.terminationType === 'jump') return 'jump';

  // Fallback to checking last instruction
  if (block.instructions.length === 0) return 'normal';
  const lastInst = block.instructions[block.instructions.length - 1];

  if (lastInst.opcode === 'REVERT' || lastInst.opcode === 'INVALID') return 'revert';
  if (lastInst.opcode === 'RETURN' || lastInst.opcode === 'STOP') return 'return';
  if (lastInst.opcode === 'JUMPI') return 'jumpi';
  if (lastInst.opcode === 'JUMP') return 'jump';
  return 'normal';
}

function CFGNode({ data }: { data: CFGNodeData }) {
  const { block, isCovered, hotspotCount, isHighlighted, coveredPcs, isEntryPoint, onPcClick } = data;

  const blockType = getBlockType(block);
  const isRevertHotspot = hotspotCount > 0;

  // Block border color based on type
  const getBorderColor = () => {
    if (isRevertHotspot) return 'border-red-500';
    if (isEntryPoint) return 'border-blue-400';
    if (block.functionSelector) return 'border-cyan-500';
    switch (blockType) {
      case 'revert': return 'border-red-500/60';
      case 'return': return 'border-green-500/60';
      case 'jumpi': return 'border-yellow-500/60';
      case 'jump': return 'border-zinc-500';
      default: return 'border-zinc-700';
    }
  };

  // Block background
  const getBgColor = () => {
    if (isRevertHotspot) return 'bg-red-950/80';
    if (isCovered) return 'bg-zinc-800/90';
    return 'bg-zinc-900/95';
  };

  // Limit displayed instructions, filter out any invalid ones
  const maxInstructions = 8;
  const validInstructions = block.instructions.filter(inst => inst && inst.pc !== undefined);
  const displayedInstructions = validInstructions.slice(0, maxInstructions);
  const hasMore = validInstructions.length > maxInstructions;

  return (
    <>
      <Handle
        type="target"
        position={Position.Top}
        className="!bg-zinc-500 !border-zinc-400 !w-2 !h-2"
      />

      <div
        className={cn(
          'min-w-[160px] max-w-[200px] rounded border shadow-lg',
          isHighlighted && 'ring-2 ring-blue-400 ring-offset-1 ring-offset-zinc-900',
          getBorderColor(),
          getBgColor()
        )}
      >
        {/* Header - Entry point or function label */}
        {(isEntryPoint || block.functionSelector) && (
          <div className={cn(
            'px-2 py-0.5 text-[9px] font-medium border-b border-zinc-700/50',
            isEntryPoint ? 'text-blue-300 bg-blue-500/20' : 'text-cyan-300 bg-cyan-500/20'
          )}>
            {isEntryPoint ? 'entrypoint' : `func:${block.functionSelector}`}
          </div>
        )}

        {/* Instructions - compact display like evmole */}
        <div className="py-1">
          {displayedInstructions.map((inst, idx) => (
            <InstructionRow
              key={`${inst.pc}-${idx}`}
              instruction={inst}
              isCovered={coveredPcs.has(inst.pc)}
              isFirst={idx === 0 && !isEntryPoint && !block.functionSelector}
              isLast={idx === displayedInstructions.length - 1 && !hasMore}
              onClick={() => onPcClick(inst.pc)}
            />
          ))}
          {hasMore && (
            <div className="px-2 text-[9px] text-zinc-500 text-center">
              ⋮ {validInstructions.length - maxInstructions} more
            </div>
          )}
        </div>

        {/* Revert hotspot indicator */}
        {isRevertHotspot && (
          <div className="px-2 py-0.5 text-[9px] text-red-400 border-t border-red-500/30 bg-red-500/10">
            {hotspotCount.toLocaleString()} reverts
          </div>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!bg-zinc-500 !border-zinc-400 !w-2 !h-2"
      />
    </>
  );
}

interface InstructionRowProps {
  instruction: DisassembledInstruction;
  isCovered: boolean;
  isFirst: boolean;
  isLast: boolean;
  onClick: () => void;
}

function InstructionRow({ instruction, isCovered, isFirst, isLast, onClick }: InstructionRowProps) {
  // Defensive check for malformed instruction data
  if (!instruction || instruction.pc === undefined || instruction.pc === null) {
    console.warn('[CFGNode] Invalid instruction:', instruction);
    return null;
  }

  const isTerminator =
    instruction.opcode === 'JUMP' ||
    instruction.opcode === 'JUMPI' ||
    instruction.opcode === 'RETURN' ||
    instruction.opcode === 'STOP' ||
    instruction.opcode === 'REVERT' ||
    instruction.opcode === 'INVALID' ||
    instruction.opcode === 'SELFDESTRUCT';

  const isJumpDest = instruction.opcode === 'JUMPDEST';

  // Opcode color
  const getOpcodeColor = () => {
    if (instruction.opcode === 'REVERT' || instruction.opcode === 'INVALID') return 'text-red-400';
    if (instruction.opcode === 'RETURN' || instruction.opcode === 'STOP') return 'text-green-400';
    if (instruction.opcode === 'JUMPI') return 'text-yellow-400';
    if (instruction.opcode === 'JUMP') return 'text-orange-400';
    if (instruction.opcode === 'JUMPDEST') return 'text-purple-400';
    if (instruction.opcode.startsWith('CALL') || instruction.opcode === 'DELEGATECALL' || instruction.opcode === 'STATICCALL') return 'text-blue-400';
    if (isCovered) return 'text-zinc-300';
    return 'text-zinc-400';
  };

  // Format PC as 4-digit hex
  const pcHex = instruction.pc.toString(16).padStart(4, '0');

  // Format args - truncate if too long
  const args = instruction.args
    ? instruction.args.length > 12
      ? instruction.args.slice(0, 10) + '…'
      : instruction.args
    : '';

  return (
    <div
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 px-2 py-px text-[10px] font-mono cursor-pointer',
        'hover:bg-zinc-700/50 transition-colors',
        isCovered && 'bg-green-500/5',
        isTerminator && 'font-semibold'
      )}
    >
      <span className="text-zinc-500 w-8 flex-shrink-0">{pcHex}</span>
      <span className={cn('flex-shrink-0', getOpcodeColor())}>
        {instruction.opcode}
      </span>
      {args && (
        <span className="text-zinc-500 truncate text-[9px]">{args}</span>
      )}
    </div>
  );
}

export default memo(CFGNode);

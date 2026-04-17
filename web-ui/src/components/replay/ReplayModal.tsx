'use client';

import { useState } from 'react';
import { X, ChevronDown, ChevronRight, CheckCircle, XCircle, AlertTriangle, Loader2, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { TxTraceResult, TxPayload } from '@/types';

// =============================================================================
// Foundry reproducer generation
// =============================================================================

const INITIAL_TIMESTAMP = 1524785992;
const INITIAL_BLOCK = 4370000;
/** Default Foundry deployer address — the test contract itself lives here */
const DEPLOYER_ADDRESS = '0x7fa9385be102ac3eac297483dd6233d62b3e1496';

function isDeployerAddress(addr: string): boolean {
  return addr.toLowerCase() === DEPLOYER_ADDRESS;
}

/** Split a string by top-level commas, respecting nested brackets */
function splitTopLevel(s: string): string[] {
  const result: string[] = [];
  let depth = 0;
  let current = '';

  for (const char of s) {
    if (char === '(' || char === '[') {
      depth++;
      current += char;
    } else if (char === ')' || char === ']') {
      depth--;
      current += char;
    } else if (char === ',' && depth === 0) {
      if (current.trim()) result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) result.push(current.trim());
  return result;
}

/**
 * Convert a DynSolValue Debug string to valid Solidity literal.
 *
 * Handles: Bool(true), Uint(0x0_U256, 256), Int(0x0_I256, 256),
 * Address(0x...), Tuple([...]), Array([...]), FixedArray([...]),
 * FixedBytes(0x..., N), String("..."), Bytes([1, 2, 3])
 */
function formatArgForSolidity(arg: string): string {
  const s = arg.trim();

  // Bool(true) / Bool(false)
  if (s.startsWith('Bool(') && s.endsWith(')')) {
    return s.slice(5, -1);
  }

  // Uint(0xHEX_U256, BITS) or Uint(0xHEX_UBITS, BITS)
  if (s.startsWith('Uint(') && s.endsWith(')')) {
    const inner = s.slice(5, -1);
    const lastComma = inner.lastIndexOf(', ');
    if (lastComma === -1) return s;
    const hexPart = inner.slice(0, lastComma).trim();
    // Strip _UXXXX suffix from ruint Debug format
    const value = hexPart.replace(/_U\d+$/, '');
    return value;
  }

  // Int(0xHEX_I256, BITS)
  if (s.startsWith('Int(') && s.endsWith(')')) {
    const inner = s.slice(4, -1);
    const lastComma = inner.lastIndexOf(', ');
    if (lastComma === -1) return s;
    const hexPart = inner.slice(0, lastComma).trim();
    const value = hexPart.replace(/_I\d+$/, '');
    return value;
  }

  // Address(0x...)
  if (s.startsWith('Address(') && s.endsWith(')')) {
    const addr = s.slice(8, -1).trim();
    return `address(${addr})`;
  }

  // Tuple([elem1, elem2, ...])
  if (s.startsWith('Tuple(') && s.endsWith(')')) {
    const inner = s.slice(6, -1).trim();
    if (inner.startsWith('[') && inner.endsWith(']')) {
      const elements = splitTopLevel(inner.slice(1, -1));
      return elements.length > 0
        ? `(${elements.map(formatArgForSolidity).join(', ')})`
        : '()';
    }
    return s;
  }

  // Array([...]) / FixedArray([...])
  for (const prefix of ['FixedArray(', 'Array(']) {
    if (s.startsWith(prefix) && s.endsWith(')')) {
      const inner = s.slice(prefix.length, -1).trim();
      if (inner.startsWith('[') && inner.endsWith(']')) {
        const elements = splitTopLevel(inner.slice(1, -1));
        return elements.length > 0
          ? `[${elements.map(formatArgForSolidity).join(', ')}]`
          : '[]';
      }
      return s;
    }
  }

  // FixedBytes(0x..., SIZE)
  if (s.startsWith('FixedBytes(') && s.endsWith(')')) {
    const inner = s.slice(11, -1);
    const lastComma = inner.lastIndexOf(', ');
    if (lastComma === -1) return s;
    const hexPart = inner.slice(0, lastComma).trim();
    // Strip _B256 or similar suffix
    return hexPart.replace(/_B\d+$/, '');
  }

  // String("...")
  if (s.startsWith('String(') && s.endsWith(')')) {
    return s.slice(7, -1); // preserves inner quotes
  }

  // Bytes([1, 2, 3])
  if (s.startsWith('Bytes(') && s.endsWith(')')) {
    const inner = s.slice(6, -1).trim();
    if (inner.startsWith('[') && inner.endsWith(']')) {
      const bytes = inner.slice(1, -1).split(',').map(b => parseInt(b.trim()));
      if (bytes.every(b => !isNaN(b) && b >= 0 && b <= 255)) {
        const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
        return `hex"${hex}"`;
      }
    }
    return s;
  }

  // Fallback: return as-is (handles plain numbers, hex strings, etc.)
  return s;
}

/** Generate a Foundry test function from a tx sequence */
function generateFoundryTest(sequence: TxPayload[]): string {
  const suffix = Math.random().toString(36).slice(2, 8);
  const lines: string[] = [];

  lines.push(`function test_repro_${suffix}() public {`);
  lines.push(`    // Initial EVM state`);
  lines.push(`    vm.warp(${INITIAL_TIMESTAMP});`);
  lines.push(`    vm.roll(${INITIAL_BLOCK});`);

  for (let i = 0; i < sequence.length; i++) {
    const tx = sequence[i];
    lines.push('');

    // Apply delay before execution (matches fuzzer behavior)
    if (tx.delayTime > 0 || tx.delayBlocks > 0) {
      if (tx.delayTime > 0) {
        lines.push(`    vm.warp(block.timestamp + ${tx.delayTime});`);
      }
      if (tx.delayBlocks > 0) {
        lines.push(`    vm.roll(block.number + ${tx.delayBlocks});`);
      }
    }

    // NoCall = delay-only transaction (no function call, just time advancement)
    if (tx.function === 'delay') {
      lines.push(`    // [${i}] NoCall — delay only`);
      continue;
    }

    const hasValue = tx.value !== '0' && tx.value !== '';

    // Raw calldata (SolCalldata) — use low-level .call()
    if (tx.function === 'raw') {
      const calldata = tx.args[0] ?? '0x';
      const hexData = calldata.startsWith('0x') ? calldata.slice(2) : calldata;
      const isSelf = isDeployerAddress(tx.target);
      const callTarget = isSelf ? 'address(this)' : `address(${tx.target})`;
      lines.push(`    // [${i}] raw calldata`);
      if (!isSelf) lines.push(`    vm.prank(address(${tx.sender}));`);
      if (hasValue) {
        lines.push(`    vm.deal(${callTarget}, ${tx.value});`);
        lines.push(`    (bool success${i}, ) = ${callTarget}.call{value: ${tx.value}}(hex"${hexData}");`);
      } else {
        lines.push(`    (bool success${i}, ) = ${callTarget}.call(hex"${hexData}");`);
      }
      continue;
    }

    // Contract creation (SolCreate)
    if (tx.function === 'create') {
      const isSelf = isDeployerAddress(tx.target);
      const bytecode = tx.args[0] ?? '0x';
      const hexData = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
      lines.push(`    // [${i}] contract creation`);
      if (!isSelf) lines.push(`    vm.prank(address(${tx.sender}));`);
      if (hasValue) {
        lines.push(`    vm.deal(address(${tx.sender}), ${tx.value});`);
      }
      lines.push(`    assembly {`);
      lines.push(`        let addr := create(${hasValue ? tx.value : '0'}, add(hex"${hexData}", 0x20), ${hexData.length / 2})`);
      lines.push(`    }`);
      continue;
    }

    // Standard SolCall
    const isSelf = isDeployerAddress(tx.target);
    const formattedArgs = tx.args.map(formatArgForSolidity).join(', ');
    const rawArgs = tx.args.join(', ');
    const comment = rawArgs.length > 80 ? rawArgs.slice(0, 77) + '...' : rawArgs;
    lines.push(`    // [${i}] ${tx.function}(${comment})`);

    // External target needs vm.prank; deployer address = self, skip prank
    if (!isSelf) lines.push(`    vm.prank(address(${tx.sender}));`);

    const callPrefix = isSelf ? '' : 'target.';
    if (hasValue) {
      lines.push(`    vm.deal(address(${isSelf ? 'this' : tx.sender}), ${tx.value});`);
      lines.push(`    ${callPrefix}${tx.function}{value: ${tx.value}}(${formattedArgs});`);
    } else {
      lines.push(`    ${callPrefix}${tx.function}(${formattedArgs});`);
    }
  }

  lines.push('}');
  return lines.join('\n');
}

interface ReplayModalProps {
  isOpen: boolean;
  onClose: () => void;
  sequence: TxPayload[];
  traces: TxTraceResult[] | null;
  loading: boolean;
  error: string | null;
}

export default function ReplayModal({
  isOpen,
  onClose,
  sequence,
  traces,
  loading,
  error,
}: ReplayModalProps) {
  const [expandedTx, setExpandedTx] = useState<number | null>(null);
  const [hideReverts, setHideReverts] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopyFoundryRepro = async () => {
    const code = generateFoundryTest(sequence);
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  const toggleTx = (index: number) => {
    setExpandedTx(expandedTx === index ? null : index);
  };

  // Helper to check if a trace is an assertion failure
  // Matches: "Assertion Failed", "assert(false)", "Panic(0x01)", "panic(0x1)"
  const isAssertionFailure = (trace: TxTraceResult) => {
    if (trace.success) return false;
    const resultLower = trace.result.toLowerCase();
    return resultLower.includes('assert') ||
           resultLower.includes('panic(0x01)') ||
           resultLower.includes('panic(0x1)') ||  // Some formatters use 0x1 instead of 0x01
           /panic\s*\(\s*0x0*1\s*\)/i.test(trace.result);  // Regex for any whitespace/zero variations
  };

  // Filter traces: hide reverts but keep assertion failures
  const filteredTraces = traces?.filter((trace) => {
    if (!hideReverts) return true;
    // Show successful transactions
    if (trace.success) return true;
    // Show assertion failures (keep these visible)
    if (isAssertionFailure(trace)) return true;
    // Hide other failures (reverts)
    return false;
  });

  const revertCount = traces?.filter(
    (t) => !t.success && !isAssertionFailure(t)
  ).length ?? 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl w-[90vw] max-w-4xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-zinc-100">
            Execution Traces
          </h2>
          <div className="flex items-center gap-4">
            {/* Copy Foundry Repro */}
            {sequence.length > 0 && (
              <button
                onClick={handleCopyFoundryRepro}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 text-xs rounded transition-colors',
                  copied
                    ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                    : 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700 border border-zinc-700'
                )}
              >
                {copied ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                {copied ? 'Copied!' : 'Copy Foundry Repro'}
              </button>
            )}
            {/* Hide Reverts checkbox */}
            {traces && traces.length > 0 && revertCount > 0 && (
              <label className="flex items-center gap-2 text-sm text-zinc-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={hideReverts}
                  onChange={(e) => setHideReverts(e.target.checked)}
                  className="w-4 h-4 rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500 focus:ring-offset-0 cursor-pointer"
                />
                Hide Reverts ({revertCount})
              </label>
            )}
            <button
              onClick={onClose}
              className="p-1 text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
              <span className="ml-3 text-zinc-400">Replaying sequence...</span>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400">
              <strong>Error:</strong> {error}
            </div>
          )}

          {!loading && !error && traces && traces.length === 0 && (
            <div className="text-center text-zinc-500 py-8">
              No transactions to replay
            </div>
          )}

          {!loading && !error && filteredTraces && filteredTraces.length > 0 && (
            <div className="space-y-2">
              {filteredTraces.map((trace) => (
                <TxTraceCard
                  key={trace.index}
                  trace={trace}
                  isExpanded={expandedTx === trace.index}
                  onToggle={() => toggleTx(trace.index)}
                />
              ))}
            </div>
          )}

          {!loading && !error && traces && traces.length > 0 && filteredTraces?.length === 0 && (
            <div className="text-center text-zinc-500 py-8">
              All transactions filtered (showing 0 of {traces.length})
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-zinc-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm bg-zinc-700 hover:bg-zinc-600 text-zinc-200 rounded transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

interface TxTraceCardProps {
  trace: TxTraceResult;
  isExpanded: boolean;
  onToggle: () => void;
}

function TxTraceCard({ trace, isExpanded, onToggle }: TxTraceCardProps) {
  // Check for assertion failures: "Assertion Failed", "assert(false)", "Panic(0x01)"
  const resultLower = trace.result.toLowerCase();
  const isAssertionFailed = !trace.success && (
    resultLower.includes('assert') ||
    resultLower.includes('panic(0x01)') ||
    resultLower.includes('panic(0x1)') ||
    /panic\s*\(\s*0x0*1\s*\)/i.test(trace.result)
  );
  const isRevert = !trace.success && !isAssertionFailed;

  // Determine background color based on result type
  const bgColor = trace.success
    ? 'bg-zinc-800/30'
    : isAssertionFailed
    ? 'bg-orange-900/30'
    : 'bg-red-900/20';

  // Determine icon and color
  const getStatusIcon = () => {
    if (trace.success) {
      return <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />;
    }
    if (isAssertionFailed) {
      return <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0" />;
    }
    return <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />;
  };

  // Result text color
  const resultColor = trace.success
    ? 'text-zinc-500'
    : isAssertionFailed
    ? 'text-orange-400'
    : 'text-red-400';

  return (
    <div className={cn(
      'border rounded-lg overflow-hidden',
      trace.success
        ? 'border-zinc-800'
        : isAssertionFailed
        ? 'border-orange-800/50'
        : 'border-red-800/50'
    )}>
      {/* Transaction header */}
      <button
        onClick={onToggle}
        className={cn(
          'w-full flex items-center gap-3 px-4 py-3 text-left',
          'hover:bg-zinc-800/50 transition-colors',
          bgColor
        )}
      >
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-zinc-400 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-zinc-400 flex-shrink-0" />
        )}

        {getStatusIcon()}

        <span className="text-zinc-400 text-sm font-mono">
          [{trace.index}]
        </span>

        <span className="text-blue-400 font-mono text-sm">
          {trace.tx.function}
        </span>

        <span className="text-zinc-500 font-mono text-sm">
          ({trace.tx.args.join(', ') || 'no args'})
        </span>

        <span className={cn('ml-auto text-xs', resultColor)}>
          {trace.result}
        </span>
      </button>

      {/* Expanded details */}
      {isExpanded && (
        <div className="border-t border-zinc-800 p-4 space-y-4 bg-zinc-900/50">
          {/* Call trace */}
          {trace.callTrace.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-zinc-400 uppercase mb-2">
                Call Trace
              </h4>
              <div className="bg-zinc-950 rounded p-3 font-mono text-xs overflow-x-auto">
                {trace.callTrace.map((entry, i) => (
                  <div
                    key={i}
                    style={{ paddingLeft: `${entry.depth * 16}px` }}
                    className={cn(
                      'py-0.5',
                      entry.success ? 'text-zinc-300' : 'text-red-400'
                    )}
                  >
                    {entry.function || `${entry.callType} ${entry.to}`}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Events */}
          {trace.events.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-zinc-400 uppercase mb-2">
                Events ({trace.events.length})
              </h4>
              <div className="space-y-1">
                {trace.events.map((event, i) => (
                  <div
                    key={i}
                    className="bg-zinc-950 rounded p-2 font-mono text-xs"
                  >
                    <span className="text-purple-400">emit </span>
                    <span className="text-zinc-300">
                      {event.name || 'Unknown'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Storage changes */}
          {trace.storageChanges.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-zinc-400 uppercase mb-2">
                Storage Changes ({trace.storageChanges.length})
              </h4>
              <div className="space-y-1">
                {trace.storageChanges.map((change, i) => (
                  <div
                    key={i}
                    className="bg-zinc-950 rounded p-2 font-mono text-xs"
                  >
                    <span className="text-yellow-400">
                      {change.contractName || change.address.slice(0, 10)}
                    </span>
                    <span className="text-zinc-500"> [slot {change.slot}]: </span>
                    <span className="text-red-400">{change.previous}</span>
                    <span className="text-zinc-500"> → </span>
                    <span className="text-green-400">{change.current}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Transaction details */}
          <div>
            <h4 className="text-xs font-semibold text-zinc-400 uppercase mb-2">
              Transaction Details
            </h4>
            <div className="bg-zinc-950 rounded p-3 font-mono text-xs space-y-1">
              <div>
                <span className="text-zinc-500">From: </span>
                <span className="text-zinc-300">{trace.tx.sender}</span>
              </div>
              <div>
                <span className="text-zinc-500">To: </span>
                <span className="text-zinc-300">{trace.tx.target}</span>
              </div>
              {trace.tx.value !== '0' && (
                <div>
                  <span className="text-zinc-500">Value: </span>
                  <span className="text-yellow-400">{trace.tx.value} wei</span>
                </div>
              )}
              <div>
                <span className="text-zinc-500">Gas Used: </span>
                <span className="text-zinc-300">{trace.gasUsed.toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

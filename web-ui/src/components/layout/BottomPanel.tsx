'use client';

import { useState } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { useCommands } from '@/hooks/useFuzzerConnection';
import { cn } from '@/lib/utils';
import { truncateAddress, truncateHash } from '@/lib/utils';
import {
  AlertTriangle,
  Play,
  ChevronUp,
  ChevronDown,
  Loader2,
} from 'lucide-react';
import type { TxPayload, TxTraceResult } from '@/types';
import ReplayModal from '@/components/replay/ReplayModal';

type BottomTab = 'reverts' | 'sequence';

interface BottomPanelProps {
  expanded: boolean;
  onToggle: () => void;
}

export default function BottomPanel({ expanded, onToggle }: BottomPanelProps) {
  const [activeTab, setActiveTab] = useState<BottomTab>('reverts');

  return (
    <div className="h-full flex flex-col bg-zinc-900 border-t border-zinc-800">
      {/* Header */}
      <div className="flex items-center justify-between px-3 h-8 flex-shrink-0 border-b border-zinc-800">
        <div className="flex items-center gap-4">
          <TabButton
            active={activeTab === 'reverts'}
            onClick={() => setActiveTab('reverts')}
            label="Revert Hotspots"
          />
          <TabButton
            active={activeTab === 'sequence'}
            onClick={() => setActiveTab('sequence')}
            label="Sequence Viewer"
          />
        </div>
        <button
          onClick={onToggle}
          className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          {expanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronUp className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Content - fills remaining space */}
      {expanded && (
        <div className="flex-1 overflow-auto min-h-0">
          {activeTab === 'reverts' && <RevertsTab />}
          {activeTab === 'sequence' && <SequenceTab />}
        </div>
      )}
    </div>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  label: string;
}

function TabButton({ active, onClick, label }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'text-xs transition-colors',
        active ? 'text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'
      )}
    >
      {label}
    </button>
  );
}

function RevertsTab() {
  const revertHotspots = useFuzzerStore((s) => s.revertHotspots);
  const highlightPc = useFuzzerStore((s) => s.highlightPc);

  if (revertHotspots.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-zinc-500">
        No revert hotspots detected
      </div>
    );
  }

  return (
    <div className="p-2 h-full overflow-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-zinc-500 text-left">
            <th className="px-2 py-1 font-medium">Location</th>
            <th className="px-2 py-1 font-medium">Function</th>
            <th className="px-2 py-1 font-medium text-right">Count</th>
            <th className="px-2 py-1 font-medium">Source</th>
          </tr>
        </thead>
        <tbody>
          {revertHotspots.map((hotspot, i) => (
            <tr
              key={`${hotspot.codehash}-${hotspot.pc}`}
              className="hover:bg-zinc-800/50 cursor-pointer"
              onClick={() => highlightPc(hotspot.pc)}
            >
              <td className="px-2 py-1">
                <span className="text-zinc-400 font-mono">
                  {truncateHash(hotspot.codehash, 4)}:
                </span>
                <span className="text-red-400 font-mono ml-1">
                  PC {hotspot.pc}
                </span>
              </td>
              <td className="px-2 py-1 text-zinc-300">
                {hotspot.functionName || '-'}
              </td>
              <td className="px-2 py-1 text-right">
                <span className="text-red-400 font-medium">
                  {hotspot.count.toLocaleString()}
                </span>
              </td>
              <td className="px-2 py-1 text-zinc-500">
                {hotspot.sourceLocation
                  ? `${hotspot.sourceLocation.file}:${hotspot.sourceLocation.line}`
                  : '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SequenceTab() {
  const corpus = useFuzzerStore((s) => s.corpus);
  const selectedCorpusEntry = useFuzzerStore((s) => s.selectedCorpusEntry);
  const tests = useFuzzerStore((s) => s.tests);
  const selectedTest = useFuzzerStore((s) => s.selectedTest);
  const { replaySequence, connected } = useCommands();

  // Replay modal state
  const [showReplayModal, setShowReplayModal] = useState(false);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayTraces, setReplayTraces] = useState<TxTraceResult[] | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);

  // Get sequence to display and raw JSON for replay
  let sequence: TxPayload[] | null = null;
  let sequenceJson: string | null = null;
  let title = '';

  if (selectedCorpusEntry) {
    const entry = corpus.find((e) => e.id === selectedCorpusEntry);
    if (entry) {
      sequence = entry.sequence;
      sequenceJson = entry.sequenceJson;
      title = `Corpus Entry #${entry.priority}`;
    }
  } else if (selectedTest) {
    const test = tests.find((t) => t.id === selectedTest);
    if (test?.failureSequence) {
      sequence = test.failureSequence;
      sequenceJson = test.failureSequenceJson ?? null;
      // Include shrinking progress in title if applicable (format: shrinking:current/limit)
      if (test.state.startsWith('shrinking')) {
        const match = test.state.match(/shrinking:(\d+)\/(\d+)/);
        if (match) {
          const current = parseInt(match[1]).toLocaleString();
          const limit = parseInt(match[2]).toLocaleString();
          title = `Shrinking: ${test.id} (${current}/${limit}, ${sequence.length} txs)`;
        } else {
          title = `Shrinking: ${test.id}`;
        }
      } else {
        title = `Failure: ${test.id}`;
      }
    }
  }

  const handleReplay = async () => {
    if (!sequenceJson) {
      setReplayError('No sequence JSON available for replay');
      setShowReplayModal(true);
      return;
    }

    console.log(`[Replay] Starting replay with ${sequenceJson.length} bytes of JSON`);
    setReplayLoading(true);
    setReplayError(null);
    setReplayTraces(null);
    setShowReplayModal(true);

    try {
      const result = await replaySequence(sequenceJson);
      if (result.success && result.traces) {
        setReplayTraces(result.traces);
      } else {
        setReplayError(result.error || 'Replay failed');
      }
    } catch (e) {
      setReplayError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setReplayLoading(false);
    }
  };

  if (!sequence) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-zinc-500">
        Select a corpus entry or failed test to view sequence
      </div>
    );
  }

  return (
    <div className="p-2 h-full flex flex-col">
      {/* Header with title and replay button */}
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-zinc-400">{title}</div>
        <button
          onClick={handleReplay}
          disabled={!connected || replayLoading || !sequenceJson}
          className={cn(
            'flex items-center gap-1.5 px-2 py-1 text-xs rounded transition-colors',
            connected && !replayLoading && sequenceJson
              ? 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30'
              : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
          )}
        >
          {replayLoading ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Play className="w-3 h-3" />
          )}
          Replay
        </button>
      </div>

      {/* Sequence list - scrollable */}
      <div className="flex-1 overflow-auto space-y-1">
        {sequence.map((tx, i) => (
          <div
            key={i}
            className="flex items-start gap-2 p-2 bg-zinc-800/50 rounded font-mono text-xs"
          >
            <span className="text-zinc-500 w-6">{i + 1}.</span>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-blue-400">{tx.function}</span>
                <span className="text-zinc-500">
                  ({tx.args.join(', ') || 'no args'})
                </span>
              </div>
              <div className="text-zinc-500 text-[10px] mt-0.5">
                <span>from: {truncateAddress(tx.sender)}</span>
                <span className="mx-2">to: {truncateAddress(tx.target)}</span>
                {tx.value !== '0' && (
                  <span className="text-yellow-400">value: {tx.value}</span>
                )}
                {(tx.delayTime > 0 || tx.delayBlocks > 0) && (
                  <span className="ml-2 text-purple-400">
                    delay: {tx.delayTime}s, {tx.delayBlocks} blocks
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Replay Modal */}
      <ReplayModal
        isOpen={showReplayModal}
        onClose={() => {
          setShowReplayModal(false);
          // Clear replay state to prevent stale data on next replay
          setReplayTraces(null);
          setReplayError(null);
        }}
        sequence={sequence}
        traces={replayTraces}
        loading={replayLoading}
        error={replayError}
      />
    </div>
  );
}

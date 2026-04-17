'use client';

import { useFuzzerStore } from '@/stores/fuzzerStore';
import { ConnectionStatus } from '@/components/common/StatusIndicator';
import { formatNumber, formatGas, formatDuration } from '@/lib/utils';
import {
  Activity,
  Cpu,
  Database,
  FlameKindling,
  Target,
  Zap,
} from 'lucide-react';

export default function TopBar() {
  const connected = useFuzzerStore((s) => s.connected);
  const connecting = useFuzzerStore((s) => s.connecting);
  const stats = useFuzzerStore((s) => s.stats);
  const coverage = useFuzzerStore((s) => s.coverage);
  const config = useFuzzerStore((s) => s.config);
  const tests = useFuzzerStore((s) => s.tests);
  const campaignState = useFuzzerStore((s) => s.campaignState);

  // Calculate test stats
  const openTests = tests.filter((t) => t.state === 'open').length;
  const failedTests = tests.filter((t) => t.state === 'solved' || t.state.startsWith('shrinking')).length;
  const passedTests = tests.filter((t) => t.state === 'passed' || t.state === 'unsolvable').length;

  // Calculate progress
  const progress = config?.testLimit
    ? Math.min(100, (stats.totalCalls / config.testLimit) * 100)
    : 0;

  return (
    <div className="flex items-center justify-between px-4 py-2 bg-zinc-900 border-b border-zinc-800">
      {/* Left: Logo and Connection */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <FlameKindling className="w-5 h-5 text-orange-500" />
          <span className="font-semibold text-sm">Recon Fuzzer</span>
        </div>
        <ConnectionStatus connected={connected} connecting={connecting} />
      </div>

      {/* Center: Stats */}
      <div className="flex items-center gap-6">
        {/* Time */}
        <Stat
          icon={<Activity className="w-3.5 h-3.5" />}
          label="Elapsed"
          value={formatDuration(stats.elapsedMs)}
        />

        {/* Calls */}
        <Stat
          icon={<Target className="w-3.5 h-3.5" />}
          label="Calls"
          value={formatNumber(stats.totalCalls)}
          subvalue={config?.testLimit ? `/ ${formatNumber(config.testLimit)}` : undefined}
        />

        {/* Coverage */}
        <Stat
          icon={<Cpu className="w-3.5 h-3.5" />}
          label="Coverage"
          value={formatNumber(coverage.totalInstructions)}
          subvalue={`${coverage.totalContracts} contracts`}
        />

        {/* Corpus */}
        <Stat
          icon={<Database className="w-3.5 h-3.5" />}
          label="Corpus"
          value={formatNumber(stats.corpusSize)}
        />

        {/* Gas */}
        <Stat
          icon={<Zap className="w-3.5 h-3.5" />}
          label="Gas"
          value={formatGas(stats.totalGas)}
        />
      </div>

      {/* Right: Campaign state, Tests and Progress */}
      <div className="flex items-center gap-4">
        {/* Campaign State Badge */}
        <CampaignStateBadge state={campaignState} />

        {/* Test Results */}
        <div className="flex items-center gap-3 text-xs">
          {failedTests > 0 && (
            <span className="text-red-400 font-medium">
              {failedTests} failed
            </span>
          )}
          {passedTests > 0 && (
            <span className="text-green-400 font-medium">
              {passedTests} passed
            </span>
          )}
          {openTests > 0 && (
            <span className="text-zinc-400">
              {openTests} open
            </span>
          )}
        </div>

        {/* Progress bar */}
        {config?.testLimit && campaignState === 'running' && (
          <div className="w-24">
            <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="text-[10px] text-zinc-500 text-right mt-0.5">
              {progress.toFixed(1)}%
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

interface StatProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  subvalue?: string;
}

function Stat({ icon, label, value, subvalue }: StatProps) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-zinc-500">{icon}</span>
      <div className="flex flex-col">
        <div className="flex items-baseline gap-1">
          <span className="text-sm font-medium text-zinc-100">{value}</span>
          {subvalue && (
            <span className="text-xs text-zinc-500">{subvalue}</span>
          )}
        </div>
        <span className="text-[10px] text-zinc-500 uppercase">{label}</span>
      </div>
    </div>
  );
}

interface CampaignStateBadgeProps {
  state: string;
}

function CampaignStateBadge({ state }: CampaignStateBadgeProps) {
  const stateConfig: Record<string, { bg: string; text: string; label: string }> = {
    idle: { bg: 'bg-zinc-700', text: 'text-zinc-300', label: 'Idle' },
    running: { bg: 'bg-green-900/50', text: 'text-green-400', label: 'Running' },
    stopping: { bg: 'bg-yellow-900/50', text: 'text-yellow-400', label: 'Stopping' },
    finished: { bg: 'bg-blue-900/50', text: 'text-blue-400', label: 'Finished' },
  };

  const config = stateConfig[state] ?? stateConfig.idle;

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${config.bg} ${config.text}`}>
      {config.label}
    </span>
  );
}

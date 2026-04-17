'use client';

import { memo, useState } from 'react';
import { Panel, PanelHeader, PanelContent } from '@/components/common/Panel';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { cn } from '@/lib/utils';
import SourceCoverageView from './SourceCoverageView';
import BytecodeHeatmap from './BytecodeHeatmap';

type ViewMode = 'source' | 'bytecode';

function CoveragePanel() {
  const [viewMode, setViewMode] = useState<ViewMode>('source');
  const sourceFiles = useFuzzerStore((s) => s.sourceFiles);
  const contracts = useFuzzerStore((s) => s.contracts);

  // Show bytecode by default if no source files
  const hasSource = sourceFiles.length > 0;
  const effectiveMode = hasSource ? viewMode : 'bytecode';

  return (
    <Panel>
      <PanelHeader>
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-zinc-400">Coverage</span>

          {/* View mode tabs */}
          <div className="flex items-center bg-zinc-900 rounded p-0.5">
            <button
              onClick={() => setViewMode('source')}
              disabled={!hasSource}
              className={cn(
                'px-2 py-0.5 text-[10px] rounded transition-colors',
                effectiveMode === 'source'
                  ? 'bg-zinc-700 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300',
                !hasSource && 'opacity-50 cursor-not-allowed'
              )}
            >
              Source
            </button>
            <button
              onClick={() => setViewMode('bytecode')}
              className={cn(
                'px-2 py-0.5 text-[10px] rounded transition-colors',
                effectiveMode === 'bytecode'
                  ? 'bg-zinc-700 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300'
              )}
            >
              Bytecode
            </button>
          </div>
        </div>

        {/* Quick stats */}
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          {hasSource ? (
            <span>{sourceFiles.length} source files</span>
          ) : (
            <span className="text-yellow-500/80">No source available</span>
          )}
          <span>•</span>
          <span>{contracts.length} contracts</span>
        </div>
      </PanelHeader>

      <PanelContent scrollable={false} className="h-full">
        {effectiveMode === 'source' ? (
          <SourceCoverageView className="h-full" />
        ) : (
          <BytecodeHeatmap className="h-full" />
        )}
      </PanelContent>
    </Panel>
  );
}

export default memo(CoveragePanel);

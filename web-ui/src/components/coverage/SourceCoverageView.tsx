'use client';

import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-solidity';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { cn } from '@/lib/utils';
import { useSourceFileContent } from '@/hooks/useContractDetails';
import type { RevertHotspot } from '@/types';

// Hook for line coverage subscription with throttling (uses backend-computed LCOV-style coverage)
function useLineCoverageForFile(filePath: string | null) {
  const [lineCoverage, setLineCoverage] = useState<Map<number, number>>(() => new Map());
  const [version, setVersion] = useState(0);
  const prevSizeRef = useRef(0);
  const throttleRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!filePath) {
      if (prevSizeRef.current > 0) {
        setLineCoverage(new Map());
        setVersion(0);
        prevSizeRef.current = 0;
      }
      return;
    }

    // Get initial value from store
    const initialCoverage = useFuzzerStore.getState().sourceLineCoverage.get(filePath);
    const initialSize = initialCoverage?.size ?? 0;
    prevSizeRef.current = initialSize;
    setLineCoverage(initialCoverage ?? new Map());

    // Subscribe with throttling - update at most every 500ms
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => state.sourceLineCoverage.get(filePath)?.size ?? 0,
      (currentSize) => {
        if (currentSize !== prevSizeRef.current) {
          if (throttleRef.current) clearTimeout(throttleRef.current);

          throttleRef.current = setTimeout(() => {
            prevSizeRef.current = currentSize;
            const coverage = useFuzzerStore.getState().sourceLineCoverage.get(filePath);
            setLineCoverage(coverage ?? new Map());
            setVersion(v => v + 1);
          }, 500);
        }
      }
    );

    return () => {
      unsubscribe();
      if (throttleRef.current) clearTimeout(throttleRef.current);
    };
  }, [filePath]);

  return { lineCoverage, version };
}

// Hook for revert hotspots with throttling (by file path)
function useRevertLinesForFile(filePath: string | null) {
  const [revertLines, setRevertLines] = useState<Map<number, number>>(() => new Map());
  const prevCountRef = useRef(0);
  const throttleRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!filePath) {
      if (revertLines.size > 0) {
        setRevertLines(new Map());
        prevCountRef.current = 0;
      }
      return;
    }

    const computeRevertLines = (hotspots: RevertHotspot[]) => {
      const map = new Map<number, number>();
      let totalCount = 0;
      for (const h of hotspots) {
        if (h.sourceLocation && h.sourceLocation.file === filePath) {
          const line = h.sourceLocation.line;
          map.set(line, (map.get(line) ?? 0) + h.count);
          totalCount += h.count;
        }
      }
      return { map, totalCount };
    };

    // Get initial value
    const initial = computeRevertLines(useFuzzerStore.getState().revertHotspots);
    prevCountRef.current = initial.totalCount;
    setRevertLines(initial.map);

    // Subscribe with throttling
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => {
        let total = 0;
        for (const h of state.revertHotspots) {
          if (h.sourceLocation && h.sourceLocation.file === filePath) {
            total += h.count;
          }
        }
        return total;
      },
      (totalCount) => {
        if (totalCount !== prevCountRef.current) {
          if (throttleRef.current) clearTimeout(throttleRef.current);

          throttleRef.current = setTimeout(() => {
            prevCountRef.current = totalCount;
            const result = computeRevertLines(useFuzzerStore.getState().revertHotspots);
            setRevertLines(result.map);
          }, 500);
        }
      }
    );

    return () => {
      unsubscribe();
      if (throttleRef.current) clearTimeout(throttleRef.current);
    };
  }, [filePath]);

  return revertLines;
}

interface SourceCoverageViewProps {
  className?: string;
}

function SourceCoverageView({ className }: SourceCoverageViewProps) {
  const selectedSourceFile = useFuzzerStore((s) => s.selectedSourceFile);
  const sourceFiles = useFuzzerStore((s) => s.sourceFiles);
  const highlightLine = useFuzzerStore((s) => s.highlightLine);

  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Subscribe to highlightedLine changes
  useEffect(() => {
    setHighlightedLine(useFuzzerStore.getState().highlightedLine);
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => state.highlightedLine,
      (line) => setHighlightedLine(line)
    );
    return unsubscribe;
  }, []);

  // Get source file summary
  const sourceFileSummary = useMemo(
    () => sourceFiles.find((f) => f.path === selectedSourceFile),
    [sourceFiles, selectedSourceFile]
  );

  // Lazy load full content
  const sourceContent = useSourceFileContent(selectedSourceFile);

  const sourceFile = useMemo(() => {
    if (!sourceContent || !selectedSourceFile) return null;
    return {
      path: selectedSourceFile,
      content: sourceContent,
      language: sourceFileSummary?.language ?? 'solidity',
    };
  }, [sourceContent, selectedSourceFile, sourceFileSummary?.language]);

  // Use backend-computed line coverage (LCOV-style)
  const { lineCoverage } = useLineCoverageForFile(selectedSourceFile);
  const revertLines = useRevertLinesForFile(selectedSourceFile);

  // Calculate coverage stats from backend line coverage
  const coverageStats = useMemo(() => {
    let coveredLines = 0;
    let totalLines = 0;

    lineCoverage.forEach((hits) => {
      totalLines++;
      if (hits > 0) {
        coveredLines++;
      }
    });

    return { coveredLines, totalLines };
  }, [lineCoverage]);

  // Scroll to highlighted line
  useEffect(() => {
    if (highlightedLine && scrollContainerRef.current) {
      const lineElement = scrollContainerRef.current.querySelector(
        `[data-line="${highlightedLine}"]`
      );
      if (lineElement) {
        lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [highlightedLine]);

  // Handle line click
  const handleLineClick = useCallback((lineNum: number) => {
    highlightLine(lineNum);
  }, [highlightLine]);

  if (!sourceFile) {
    return (
      <div className={cn('flex flex-col h-full', className)}>
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 text-xs">
          <span className="text-zinc-400">Source</span>
          <span className="text-zinc-500">
            {sourceFiles.length === 0 ? 'No source files' : 'Select a file'}
          </span>
        </div>
        <div className="flex-1 flex items-center justify-center text-sm text-zinc-500">
          {sourceFiles.length === 0
            ? 'No source files available'
            : 'Select a source file from the sidebar'}
        </div>
      </div>
    );
  }

  const lines = sourceFile.content.split('\n');

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 text-xs">
        <div className="flex items-center gap-3">
          <span className="text-zinc-400">Source</span>
          <span className="text-zinc-500 truncate max-w-[200px]">
            {sourceFile.path.split('/').pop()}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-zinc-500">{lines.length} lines</span>
          {coverageStats.totalLines > 0 && (
            <>
              <span className="text-zinc-500">
                {coverageStats.coveredLines}/{coverageStats.totalLines}
              </span>
              <span
                className={cn(
                  coverageStats.coveredLines > 0 ? 'text-green-400' : 'text-zinc-500'
                )}
              >
                {((coverageStats.coveredLines / coverageStats.totalLines) * 100).toFixed(1)}%
              </span>
            </>
          )}
        </div>
      </div>

      {/* Code view */}
      <div ref={scrollContainerRef} className="flex-1 overflow-auto font-mono text-xs">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line: string, i: number) => {
              const lineNum = i + 1;
              const hits = lineCoverage.get(lineNum) ?? 0;
              const isCovered = hits > 0;
              const hasCoverage = lineCoverage.has(lineNum);
              const revertCount = revertLines.get(lineNum) ?? 0;
              const isRevertHotspot = revertCount > 0;
              const isHighlighted = highlightedLine === lineNum;

              return (
                <tr
                  key={lineNum}
                  data-line={lineNum}
                  onClick={() => handleLineClick(lineNum)}
                  className={cn(
                    'hover:bg-zinc-800/50 cursor-pointer transition-colors',
                    isHighlighted && 'bg-blue-500/20',
                    isRevertHotspot && !isHighlighted && 'bg-red-500/20',
                    isCovered && !isRevertHotspot && !isHighlighted && 'bg-green-500/10'
                  )}
                >
                  {/* Line number */}
                  <td className="w-12 text-right pr-3 select-none text-zinc-600 border-r border-zinc-800 sticky left-0 bg-zinc-950">
                    {lineNum}
                  </td>

                  {/* Coverage indicator */}
                  <td className="w-6 text-center">
                    {isRevertHotspot ? (
                      <span className="text-red-400 animate-pulse" title={`${revertCount} reverts`}>
                        !
                      </span>
                    ) : hasCoverage ? (
                      <span className={isCovered ? 'text-green-400' : 'text-zinc-700'}>
                        {isCovered ? '●' : '○'}
                      </span>
                    ) : null}
                  </td>

                  {/* Hit count (if covered) */}
                  <td className="w-8 text-right pr-2 text-zinc-600 text-[10px]">
                    {hits > 0 && hits}
                  </td>

                  {/* Code */}
                  <td className="pl-2 whitespace-pre">
                    <HighlightedLine code={line} language="solidity" />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface HighlightedLineProps {
  code: string;
  language: string;
}

const HighlightedLine = memo(function HighlightedLine({ code, language }: HighlightedLineProps) {
  const html = useMemo(() => {
    if (!code.trim()) return '';
    try {
      return Prism.highlight(
        code,
        Prism.languages[language] ?? Prism.languages.plain,
        language
      );
    } catch {
      return code;
    }
  }, [code, language]);

  return (
    <code
      className="language-solidity"
      dangerouslySetInnerHTML={{ __html: html || code }}
    />
  );
});

export default memo(SourceCoverageView);

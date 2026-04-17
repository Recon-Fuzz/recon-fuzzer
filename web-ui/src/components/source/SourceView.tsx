'use client';

import { useMemo, useEffect, useRef } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-solidity';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { Panel, PanelHeader, PanelContent } from '@/components/common/Panel';
import { cn } from '@/lib/utils';
import { useContractDetails, useSourceFileContent } from '@/hooks/useContractDetails';

export default function SourceView() {
  const selectedSourceFile = useFuzzerStore((s) => s.selectedSourceFile);
  const sourceFiles = useFuzzerStore((s) => s.sourceFiles);
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const contracts = useFuzzerStore((s) => s.contracts);
  const coverage = useFuzzerStore((s) => s.coverage);
  const revertHotspots = useFuzzerStore((s) => s.revertHotspots);
  const highlightedLine = useFuzzerStore((s) => s.highlightedLine);
  const highlightLine = useFuzzerStore((s) => s.highlightLine);

  const codeRef = useRef<HTMLPreElement>(null);

  // Get summaries
  const sourceFileSummary = sourceFiles.find((f) => f.path === selectedSourceFile);
  const contractSummary = contracts.find((c) => c.name === selectedContract);

  // Lazy load full content
  const contractDetails = useContractDetails(selectedContract);
  const sourceContent = useSourceFileContent(selectedSourceFile);

  // Use full details when available, fall back to summary for codehash
  const contract = contractDetails;
  const sourceFile = sourceContent && selectedSourceFile ? { path: selectedSourceFile, content: sourceContent, language: sourceFileSummary?.language ?? 'solidity' } : null;

  // Parse source map and compute line coverage
  const lineCoverage = useMemo(() => {
    if (!contract?.sourceMap || !sourceFile || !contractSummary?.codehash) {
      return new Map<number, { covered: boolean; pcs: number[] }>();
    }

    const coverageMap = new Map<number, { covered: boolean; pcs: number[] }>();
    const coveredPcs = coverage.runtime.get(contractSummary.codehash) ?? new Set();

    // Parse the source map
    // Format: s:l:f:j:m;s:l:f:j:m;...
    // s = start (byte offset), l = length, f = file index, j = jump type, m = modifier depth
    try {
      const entries = contract.sourceMap.split(';');
      let currentStart = 0;
      let currentLength = 0;
      let currentFile = 0;

      entries.forEach((entry: string, pc: number) => {
        const parts = entry.split(':');

        if (parts[0] !== '') currentStart = parseInt(parts[0], 10);
        if (parts[1] !== '') currentLength = parseInt(parts[1], 10);
        if (parts[2] !== '') currentFile = parseInt(parts[2], 10);

        // Only process if file matches and has valid range
        if (currentFile === 0 && currentStart >= 0 && currentLength >= 0) {
          // Convert byte offset to line number
          const line = byteOffsetToLine(sourceFile.content, currentStart);

          if (line > 0) {
            const existing = coverageMap.get(line) ?? { covered: false, pcs: [] };
            existing.pcs.push(pc);
            if (coveredPcs.has(pc)) {
              existing.covered = true;
            }
            coverageMap.set(line, existing);
          }
        }
      });
    } catch (e) {
      console.error('Failed to parse source map:', e);
    }

    return coverageMap;
  }, [contract, contractSummary?.codehash, sourceFile, coverage.runtime]);

  // Get revert hotspot lines
  const revertLines = useMemo(() => {
    if (!contractSummary?.codehash) return new Set<number>();

    const lines = new Set<number>();
    for (const h of revertHotspots) {
      if (h.codehash === contractSummary.codehash && h.sourceLocation) {
        lines.add(h.sourceLocation.line);
      }
    }
    return lines;
  }, [contractSummary?.codehash, revertHotspots]);

  // Highlight syntax
  useEffect(() => {
    if (codeRef.current) {
      Prism.highlightElement(codeRef.current);
    }
  }, [sourceFile?.content]);

  // Scroll to highlighted line
  useEffect(() => {
    if (highlightedLine && codeRef.current) {
      const lineElement = codeRef.current.querySelector(
        `[data-line="${highlightedLine}"]`
      );
      if (lineElement) {
        lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [highlightedLine]);

  // Calculate coverage stats
  const coverageStats = useMemo(() => {
    let coveredLines = 0;
    let totalLines = 0;

    lineCoverage.forEach((data) => {
      if (data.pcs.length > 0) {
        totalLines++;
        if (data.covered) {
          coveredLines++;
        }
      }
    });

    return { coveredLines, totalLines };
  }, [lineCoverage]);

  if (!sourceFile) {
    return (
      <Panel title="Source">
        <PanelContent>
          <div className="flex items-center justify-center h-full text-sm text-zinc-500">
            {sourceFiles.length === 0
              ? 'No source files available'
              : 'Select a source file to view'}
          </div>
        </PanelContent>
      </Panel>
    );
  }

  const lines = sourceFile.content.split('\n');

  return (
    <Panel>
      <PanelHeader>
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-zinc-400">Source</span>
          <span className="text-xs text-zinc-500">
            {sourceFile.path.split('/').pop()}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs">
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
      </PanelHeader>
      <PanelContent>
        <div className="font-mono text-xs overflow-auto h-full">
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line: string, i: number) => {
                const lineNum = i + 1;
                const coverageData = lineCoverage.get(lineNum);
                const isCovered = coverageData?.covered ?? false;
                const hasCoverage = coverageData?.pcs.length ?? 0 > 0;
                const isRevertHotspot = revertLines.has(lineNum);
                const isHighlighted = highlightedLine === lineNum;

                return (
                  <tr
                    key={lineNum}
                    data-line={lineNum}
                    onClick={() => highlightLine(lineNum)}
                    className={cn(
                      'hover:bg-zinc-800/50 cursor-pointer transition-colors',
                      isHighlighted && 'bg-blue-500/20',
                      isRevertHotspot && 'bg-red-500/20 animate-pulse',
                      isCovered && !isRevertHotspot && !isHighlighted && 'bg-green-500/10'
                    )}
                  >
                    {/* Line number */}
                    <td className="w-12 text-right pr-3 select-none text-zinc-600 border-r border-zinc-800">
                      {lineNum}
                    </td>

                    {/* Coverage indicator */}
                    <td className="w-4 text-center">
                      {isRevertHotspot ? (
                        <span className="text-red-400">!</span>
                      ) : hasCoverage ? (
                        <span className={isCovered ? 'text-green-400' : 'text-zinc-700'}>
                          {isCovered ? '●' : '○'}
                        </span>
                      ) : null}
                    </td>

                    {/* Code */}
                    <td className="pl-2">
                      <HighlightedLine code={line} language="solidity" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </PanelContent>
    </Panel>
  );
}

interface HighlightedLineProps {
  code: string;
  language: string;
}

function HighlightedLine({ code, language }: HighlightedLineProps) {
  // Use Prism to highlight single line
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
      className="language-solidity whitespace-pre"
      dangerouslySetInnerHTML={{ __html: html || code }}
    />
  );
}

/**
 * Convert byte offset in source to line number
 */
function byteOffsetToLine(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source[i] === '\n') {
      line++;
    }
  }
  return line;
}

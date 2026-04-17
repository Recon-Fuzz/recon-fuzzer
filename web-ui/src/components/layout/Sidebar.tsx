'use client';

import { useState, useMemo } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { cn } from '@/lib/utils';
import {
  ChevronDown,
  ChevronRight,
  FileCode,
  FolderOpen,
  FlaskConical,
  Database,
  Users,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  Maximize2,
} from 'lucide-react';

type SidebarTab = 'files' | 'tests' | 'corpus' | 'workers';

export default function Sidebar() {
  const [activeTab, setActiveTab] = useState<SidebarTab>('files');

  return (
    <div className="w-56 flex flex-col bg-zinc-900 border-r border-zinc-800">
      {/* Tab buttons */}
      <div className="flex border-b border-zinc-800">
        <TabButton
          active={activeTab === 'files'}
          onClick={() => setActiveTab('files')}
          icon={<FolderOpen className="w-4 h-4" />}
          label="Files"
        />
        <TabButton
          active={activeTab === 'tests'}
          onClick={() => setActiveTab('tests')}
          icon={<FlaskConical className="w-4 h-4" />}
          label="Tests"
        />
        <TabButton
          active={activeTab === 'corpus'}
          onClick={() => setActiveTab('corpus')}
          icon={<Database className="w-4 h-4" />}
          label="Corpus"
        />
        <TabButton
          active={activeTab === 'workers'}
          onClick={() => setActiveTab('workers')}
          icon={<Users className="w-4 h-4" />}
          label="Workers"
        />
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto">
        {activeTab === 'files' && <FilesTab />}
        {activeTab === 'tests' && <TestsTab />}
        {activeTab === 'corpus' && <CorpusTab />}
        {activeTab === 'workers' && <WorkersTab />}
      </div>
    </div>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}

function TabButton({ active, onClick, icon, label }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex-1 flex flex-col items-center gap-1 py-2 text-xs transition-colors',
        active
          ? 'text-blue-400 border-b-2 border-blue-400'
          : 'text-zinc-500 hover:text-zinc-300'
      )}
      title={label}
    >
      {icon}
    </button>
  );
}

// Tree node structure for folder hierarchy
interface FileTreeNode {
  name: string;
  path: string;
  isFile: boolean;
  children: Map<string, FileTreeNode>;
}

// Build a tree structure from source file paths
function buildFileTree(files: { path: string }[]): FileTreeNode {
  const root: FileTreeNode = {
    name: '',
    path: '',
    isFile: false,
    children: new Map(),
  };

  // Use a Set to deduplicate paths
  const uniquePaths = new Set(files.map(f => f.path));

  for (const path of uniquePaths) {
    const parts = path.split('/').filter(Boolean);
    let current = root;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isFile = i === parts.length - 1;
      const currentPath = parts.slice(0, i + 1).join('/');

      if (!current.children.has(part)) {
        current.children.set(part, {
          name: part,
          path: currentPath,
          isFile,
          children: new Map(),
        });
      }
      current = current.children.get(part)!;
    }
  }

  return root;
}

// Recursive folder/file tree component
interface FolderNodeProps {
  node: FileTreeNode;
  depth: number;
  expandedFolders: Set<string>;
  toggleFolder: (path: string) => void;
  selectedSourceFile: string | null;
  selectSourceFile: (path: string) => void;
}

function FolderNode({
  node,
  depth,
  expandedFolders,
  toggleFolder,
  selectedSourceFile,
  selectSourceFile,
}: FolderNodeProps) {
  const isExpanded = expandedFolders.has(node.path);
  const sortedChildren = Array.from(node.children.values()).sort((a, b) => {
    // Folders first, then files, alphabetically
    if (a.isFile !== b.isFile) return a.isFile ? 1 : -1;
    return a.name.localeCompare(b.name);
  });

  if (node.isFile) {
    return (
      <button
        onClick={() => selectSourceFile(node.path)}
        className={cn(
          'w-full flex items-center gap-2 px-2 py-1 text-xs rounded',
          selectedSourceFile === node.path
            ? 'bg-blue-500/20 text-blue-400'
            : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'
        )}
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
      >
        <FileCode className="w-3 h-3 flex-shrink-0" />
        <span className="truncate">{node.name}</span>
      </button>
    );
  }

  return (
    <div>
      <button
        onClick={() => toggleFolder(node.path)}
        className="w-full flex items-center gap-1 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200"
        style={{ paddingLeft: `${depth * 12}px` }}
      >
        {isExpanded ? (
          <ChevronDown className="w-3 h-3 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-3 h-3 flex-shrink-0" />
        )}
        <FolderOpen className="w-3 h-3 flex-shrink-0 text-yellow-500" />
        <span className="truncate">{node.name}</span>
        <span className="text-zinc-600 text-[10px] ml-auto">
          {node.children.size}
        </span>
      </button>
      {isExpanded && (
        <div>
          {sortedChildren.map((child) => (
            <FolderNode
              key={child.path}
              node={child}
              depth={depth + 1}
              expandedFolders={expandedFolders}
              toggleFolder={toggleFolder}
              selectedSourceFile={selectedSourceFile}
              selectSourceFile={selectSourceFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function FilesTab() {
  const allContracts = useFuzzerStore((s) => s.contracts);
  const coverageRuntime = useFuzzerStore((s) => s.coverage.runtime);
  const sourceFiles = useFuzzerStore((s) => s.sourceFiles);
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const selectedSourceFile = useFuzzerStore((s) => s.selectedSourceFile);
  const selectContract = useFuzzerStore((s) => s.selectContract);
  const selectSourceFile = useFuzzerStore((s) => s.selectSourceFile);

  // Filter contracts to only show those with coverage (hit during fuzzing)
  const contracts = useMemo(() => {
    return allContracts.filter((c) => coverageRuntime.has(c.codehash));
  }, [allContracts, coverageRuntime]);

  const [contractsExpanded, setContractsExpanded] = useState(true);
  const [sourcesExpanded, setSourcesExpanded] = useState(true);
  // Default expanded folders - src and test are expanded by default
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(
    () => new Set(['src', 'test', 'contracts', 'tests'])
  );

  const toggleFolder = (path: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  // Build file tree from source files
  const fileTree = buildFileTree(sourceFiles);
  const rootChildren = Array.from(fileTree.children.values()).sort((a, b) => {
    // Folders first, then files, alphabetically
    if (a.isFile !== b.isFile) return a.isFile ? 1 : -1;
    return a.name.localeCompare(b.name);
  });

  // Count unique files (for display)
  const uniqueFileCount = new Set(sourceFiles.map(f => f.path)).size;

  return (
    <div className="py-2">
      {/* Contracts */}
      <div>
        <button
          onClick={() => setContractsExpanded(!contractsExpanded)}
          className="w-full flex items-center gap-1 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200"
        >
          {contractsExpanded ? (
            <ChevronDown className="w-3 h-3" />
          ) : (
            <ChevronRight className="w-3 h-3" />
          )}
          <span className="uppercase font-medium">Contracts</span>
          <span className="text-zinc-600 ml-auto">{contracts.length}</span>
        </button>
        {contractsExpanded && (
          <div className="ml-2">
            {contracts.map((contract) => (
              <button
                key={contract.qualifiedName}
                onClick={() => {
                  selectContract(contract.name);
                  // Also select the corresponding source file
                  // qualifiedName format is "path/to/file.sol:ContractName"
                  const filePath = contract.qualifiedName.split(':')[0];
                  if (filePath && sourceFiles.some(f => f.path === filePath)) {
                    selectSourceFile(filePath);
                  }
                }}
                className={cn(
                  'w-full flex items-center gap-2 px-2 py-1 text-xs rounded',
                  selectedContract === contract.name
                    ? 'bg-blue-500/20 text-blue-400'
                    : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'
                )}
              >
                <FileCode className="w-3 h-3 flex-shrink-0" />
                <span className="truncate">{contract.name}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Source Files - Hierarchical */}
      {sourceFiles.length > 0 && (
        <div className="mt-2">
          <button
            onClick={() => setSourcesExpanded(!sourcesExpanded)}
            className="w-full flex items-center gap-1 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200"
          >
            {sourcesExpanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            <span className="uppercase font-medium">Sources</span>
            <span className="text-zinc-600 ml-auto">{uniqueFileCount}</span>
          </button>
          {sourcesExpanded && (
            <div>
              {rootChildren.map((node) => (
                <FolderNode
                  key={node.path}
                  node={node}
                  depth={1}
                  expandedFolders={expandedFolders}
                  toggleFolder={toggleFolder}
                  selectedSourceFile={selectedSourceFile}
                  selectSourceFile={selectSourceFile}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TestsTab() {
  const tests = useFuzzerStore((s) => s.tests);
  const selectedTest = useFuzzerStore((s) => s.selectedTest);
  const selectTest = useFuzzerStore((s) => s.selectTest);

  const getTestIcon = (state: string) => {
    // Handle "shrinking:N" format (e.g., "shrinking:5")
    if (state.startsWith('shrinking')) {
      return <Loader2 className="w-3 h-3 text-yellow-400 animate-spin" />;
    }
    switch (state) {
      case 'passed':
      case 'unsolvable':
        return <CheckCircle2 className="w-3 h-3 text-green-400" />;
      case 'solved':
        return <XCircle className="w-3 h-3 text-red-400" />;
      default:
        return <AlertCircle className="w-3 h-3 text-zinc-500" />;
    }
  };

  return (
    <div className="py-2 px-2">
      {tests.length === 0 ? (
        <div className="text-xs text-zinc-500 text-center py-4">
          No tests found
        </div>
      ) : (
        <div className="space-y-1">
          {tests.map((test) => {
            // Extract shrinking progress if applicable (format: shrinking:current/limit)
            const shrinkMatch = test.state.match(/shrinking:(\d+)\/(\d+)/);
            const shrinkCurrent = shrinkMatch ? parseInt(shrinkMatch[1]) : null;
            const shrinkLimit = shrinkMatch ? parseInt(shrinkMatch[2]) : null;
            const shrinkPercent = shrinkCurrent !== null && shrinkLimit ?
              Math.round((shrinkCurrent / shrinkLimit) * 100) : null;

            return (
              <button
                key={test.id}
                onClick={() => selectTest(test.id)}
                className={cn(
                  'w-full flex items-center gap-2 px-2 py-1.5 text-xs rounded',
                  selectedTest === test.id
                    ? 'bg-blue-500/20 text-blue-400'
                    : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'
                )}
              >
                {getTestIcon(test.state)}
                <span className="truncate flex-1 text-left">{test.id}</span>
                {shrinkPercent !== null && (
                  <span className="text-[10px] text-yellow-400">{shrinkPercent}%</span>
                )}
                {test.value && shrinkPercent === null && (
                  <span className="text-[10px] text-zinc-500">{test.value}</span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CorpusTab() {
  const corpus = useFuzzerStore((s) => s.corpus);
  const selectedCorpusEntry = useFuzzerStore((s) => s.selectedCorpusEntry);
  const selectCorpusEntry = useFuzzerStore((s) => s.selectCorpusEntry);

  return (
    <div className="py-2 px-2">
      {corpus.length === 0 ? (
        <div className="text-xs text-zinc-500 text-center py-4">
          No corpus entries yet
        </div>
      ) : (
        <div className="space-y-1">
          {corpus.slice(0, 50).map((entry) => (
            <button
              key={entry.id}
              onClick={() => selectCorpusEntry(entry.id)}
              className={cn(
                'w-full flex items-center gap-2 px-2 py-1.5 text-xs rounded',
                selectedCorpusEntry === entry.id
                  ? 'bg-blue-500/20 text-blue-400'
                  : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'
              )}
            >
              <span className="text-[10px] text-zinc-600">#{entry.priority}</span>
              <span className="truncate flex-1 text-left">
                {entry.sequence.length} calls
              </span>
              <span className="text-[10px] text-zinc-500">
                +{entry.coverageContribution}
              </span>
            </button>
          ))}
          {corpus.length > 50 && (
            <div className="text-xs text-zinc-500 text-center py-2">
              +{corpus.length - 50} more
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function WorkersTab() {
  const workers = useFuzzerStore((s) => s.workers);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'fuzzing':
        return 'text-green-400';
      case 'shrinking':
        return 'text-yellow-400';
      case 'idle':
        return 'text-zinc-500';
      default:
        return 'text-blue-400';
    }
  };

  return (
    <div className="py-2 px-2">
      {workers.length === 0 ? (
        <div className="text-xs text-zinc-500 text-center py-4">
          No workers running
        </div>
      ) : (
        <div className="space-y-2">
          {workers.map((worker) => (
            <div
              key={worker.id}
              className="p-2 bg-zinc-800/50 rounded text-xs"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium">
                  Worker {worker.id}
                  {worker.isInteractive && (
                    <span className="ml-1 text-[10px] text-purple-400">
                      (interactive)
                    </span>
                  )}
                </span>
                <span className={getStatusColor(worker.status.type || 'idle')}>
                  {worker.status.type || 'idle'}
                </span>
              </div>
              <div className="flex gap-3 text-zinc-500">
                <span>{worker.calls.toLocaleString()} calls</span>
                <span>{worker.sequences.toLocaleString()} seqs</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

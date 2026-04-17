/**
 * Zustand store for fuzzer state management
 */

import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type {
  ContractInfo,
  ContractSummary,
  SourceFile,
  SourceFileSummary,
  ConfigSummary,
  CoverageSnapshot,
  CoverageDelta,
  ContractCoverage,
  CorpusEntryPayload,
  TestInfo,
  WorkerSnapshot,
  WorkerInfo,
  RevertHotspot,
  InitPayload,
  StateUpdatePayload,
  CampaignState,
  SourceLineCoverage,
  ContractPcMapping,
} from '@/types';

// ============================================================================
// State Interface
// ============================================================================

interface CoverageState {
  runtime: Map<string, Set<number>>; // codehash -> Set of covered PCs
  init: Map<string, Set<number>>;
  totalInstructions: number;
  totalContracts: number;
}

interface FuzzerState {
  // Connection state
  connected: boolean;
  connecting: boolean;
  error: string | null;

  // Campaign state
  campaignState: CampaignState;

  // Static data (from init) - summaries for fast initial load
  contracts: ContractSummary[];
  sourceFiles: SourceFileSummary[];
  config: ConfigSummary | null;
  workerInfo: WorkerInfo[];

  // Cache for full details (lazy loaded)
  contractDetails: Map<string, ContractInfo>;
  sourceFileContents: Map<string, SourceFile>;

  // Dynamic state
  coverage: CoverageState;
  workers: WorkerSnapshot[];
  corpus: CorpusEntryPayload[];
  tests: TestInfo[];
  revertHotspots: RevertHotspot[];

  // Source-level coverage (from backend - LCOV-style)
  sourceLineCoverage: Map<string, Map<number, number>>; // path -> (line -> hits)
  // PC to source mappings (for bytecode -> source navigation)
  pcMappings: Map<string, Map<number, { file: string; line: number; column: number }>>; // codehash -> (pc -> location)

  // Statistics
  stats: {
    elapsedMs: number;
    totalCalls: number;
    totalSequences: number;
    totalGas: number;
    corpusSize: number;
  };

  // UI selection state
  selectedContract: string | null;
  selectedSourceFile: string | null;
  selectedCorpusEntry: string | null;
  selectedTest: string | null;
  highlightedPc: number | null;
  highlightedLine: number | null;

  // Actions
  setConnected: (connected: boolean) => void;
  setConnecting: (connecting: boolean) => void;
  setError: (error: string | null) => void;

  // Data actions
  handleInit: (payload: InitPayload) => void;
  handleStateUpdate: (payload: StateUpdatePayload) => void;
  applyCoverageDelta: (delta: CoverageDelta) => void;
  addCorpusEntry: (entry: CorpusEntryPayload) => void;
  updateTest: (testId: string, updates: Partial<TestInfo>) => void;

  // Selection actions
  selectContract: (name: string | null) => void;
  selectSourceFile: (path: string | null) => void;
  selectCorpusEntry: (id: string | null) => void;
  selectTest: (id: string | null) => void;
  highlightPc: (pc: number | null) => void;
  highlightLine: (line: number | null) => void;

  // Utility methods
  getContractByName: (name: string) => ContractSummary | undefined;
  getCachedContractDetails: (name: string) => ContractInfo | undefined;
  cacheContractDetails: (name: string, details: ContractInfo) => void;
  getCachedSourceFile: (path: string) => SourceFile | undefined;
  cacheSourceFile: (path: string, file: SourceFile) => void;
  getCoverageForContract: (codehash: string) => Set<number>;
  isRevertHotspot: (codehash: string, pc: number) => boolean;
  getLineCoverageForFile: (path: string) => Map<number, number> | undefined;
  getPcToSourceMapping: (codehash: string) => Map<number, { file: string; line: number; column: number }> | undefined;
  reset: () => void;

  // Campaign state actions
  setCampaignState: (state: CampaignState) => void;
}

// ============================================================================
// Initial State
// ============================================================================

const initialCoverageState: CoverageState = {
  runtime: new Map(),
  init: new Map(),
  totalInstructions: 0,
  totalContracts: 0,
};

const initialStats = {
  elapsedMs: 0,
  totalCalls: 0,
  totalSequences: 0,
  totalGas: 0,
  corpusSize: 0,
};


// ============================================================================
// Store
// ============================================================================

export const useFuzzerStore = create<FuzzerState>()(
  subscribeWithSelector((set, get) => ({
    // Connection state
    connected: false,
    connecting: false,
    error: null,

    // Campaign state
    campaignState: 'idle' as CampaignState,

    // Static data (summaries for fast initial load)
    contracts: [],
    sourceFiles: [],
    config: null,
    workerInfo: [],

    // Cache for full details (lazy loaded)
    contractDetails: new Map(),
    sourceFileContents: new Map(),

    // Dynamic state
    coverage: initialCoverageState,
    workers: [],
    corpus: [],
    tests: [],
    revertHotspots: [],

    // Source-level coverage (from backend)
    sourceLineCoverage: new Map(),
    // PC to source mappings
    pcMappings: new Map(),

    // Statistics
    stats: initialStats,

    // UI selection state
    selectedContract: null,
    selectedSourceFile: null,
    selectedCorpusEntry: null,
    selectedTest: null,
    highlightedPc: null,
    highlightedLine: null,

    // ========================================================================
    // Connection Actions
    // ========================================================================

    setConnected: (connected) => set({ connected, connecting: false }),
    setConnecting: (connecting) => set({ connecting }),
    setError: (error) => set({ error }),

    // ========================================================================
    // Data Actions
    // ========================================================================

    handleInit: (payload) => {
      // Build coverage maps from snapshot
      const runtimeMap = new Map<string, Set<number>>();
      const initMap = new Map<string, Set<number>>();

      for (const cov of payload.coverage.runtime) {
        runtimeMap.set(cov.codehash, new Set(cov.coveredPcs));
      }
      for (const cov of payload.coverage.init) {
        initMap.set(cov.codehash, new Set(cov.coveredPcs));
      }

      // Limit corpus to prevent memory issues (backend has full corpus)
      const MAX_CORPUS_ENTRIES = 100;
      const limitedCorpus = payload.corpus.length > MAX_CORPUS_ENTRIES
        ? payload.corpus.slice(-MAX_CORPUS_ENTRIES)
        : payload.corpus;

      // Build source line coverage map from backend data
      const sourceLineCoverage = new Map<string, Map<number, number>>();
      for (const fileCov of payload.sourceLineCoverage ?? []) {
        const lineMap = new Map<number, number>();
        for (const line of fileCov.lines) {
          lineMap.set(line.line, line.hits);
        }
        sourceLineCoverage.set(fileCov.path, lineMap);
      }

      // Build PC to source mapping from backend data
      const pcMappings = new Map<string, Map<number, { file: string; line: number; column: number }>>();
      for (const contractMapping of payload.pcMappings ?? []) {
        const pcMap = new Map<number, { file: string; line: number; column: number }>();
        for (const entry of contractMapping.pcToSource) {
          pcMap.set(entry.pc, {
            file: entry.file,
            line: entry.line,
            column: entry.column,
          });
        }
        pcMappings.set(contractMapping.codehash, pcMap);
      }

      set({
        contracts: payload.contracts,
        sourceFiles: payload.sourceFiles,
        config: payload.config,
        workerInfo: payload.workers,
        corpus: limitedCorpus,
        tests: payload.tests,
        coverage: {
          runtime: runtimeMap,
          init: initMap,
          totalInstructions: payload.coverage.totalInstructions,
          totalContracts: payload.coverage.totalContracts,
        },
        campaignState: payload.campaignState ?? 'idle',
        sourceLineCoverage,
        pcMappings,
        // Auto-select first contract if none selected
        selectedContract: get().selectedContract ?? payload.contracts[0]?.name ?? null,
        // Auto-select first source file if none selected
        selectedSourceFile: get().selectedSourceFile ?? payload.sourceFiles[0]?.path ?? null,
      });
    },

    handleStateUpdate: (payload) => {
      const state = get();

      // Apply coverage delta
      if (payload.coverageDelta.newInstructions > 0) {
        state.applyCoverageDelta(payload.coverageDelta);
      }

      // Update source line coverage if provided (only sent when coverage changes)
      let sourceLineCoverageUpdate: Map<string, Map<number, number>> | undefined;
      if (payload.sourceLineCoverage && payload.sourceLineCoverage.length > 0) {
        sourceLineCoverageUpdate = new Map<string, Map<number, number>>();
        for (const fileCov of payload.sourceLineCoverage) {
          const lineMap = new Map<number, number>();
          for (const line of fileCov.lines) {
            lineMap.set(line.line, line.hits);
          }
          sourceLineCoverageUpdate.set(fileCov.path, lineMap);
        }
      }

      set({
        workers: payload.workers,
        revertHotspots: payload.revertHotspots,
        stats: {
          elapsedMs: payload.elapsedMs,
          totalCalls: payload.totalCalls,
          totalSequences: payload.totalSequences,
          totalGas: payload.totalGas,
          corpusSize: payload.corpusSize,
        },
        // Update campaign state if provided
        ...(payload.campaignState && { campaignState: payload.campaignState }),
        // Update source line coverage if provided
        ...(sourceLineCoverageUpdate && { sourceLineCoverage: sourceLineCoverageUpdate }),
      });
    },

    applyCoverageDelta: (delta) => {
      // Skip if no new coverage
      if (delta.newRuntime.length === 0 && delta.newInit.length === 0) {
        return;
      }

      set((state) => {
        // IMPORTANT: Mutate existing Maps/Sets in place to avoid memory explosion
        // We only create a new coverage object reference for React to detect changes
        const { runtime, init } = state.coverage;

        // Merge new runtime coverage (mutate in place)
        for (const cov of delta.newRuntime) {
          let existing = runtime.get(cov.codehash);
          if (!existing) {
            existing = new Set();
            runtime.set(cov.codehash, existing);
          }
          for (const pc of cov.coveredPcs) {
            existing.add(pc);
          }
        }

        // Merge new init coverage (mutate in place)
        for (const cov of delta.newInit) {
          let existing = init.get(cov.codehash);
          if (!existing) {
            existing = new Set();
            init.set(cov.codehash, existing);
          }
          for (const pc of cov.coveredPcs) {
            existing.add(pc);
          }
        }

        // Calculate totals
        let totalInstructions = 0;
        runtime.forEach((pcs) => {
          totalInstructions += pcs.size;
        });
        init.forEach((pcs) => {
          totalInstructions += pcs.size;
        });

        // Return new coverage object reference (same Maps) to trigger re-render
        return {
          coverage: {
            runtime,
            init,
            totalInstructions,
            totalContracts: runtime.size + init.size,
          },
        };
      });
    },

    addCorpusEntry: (entry) => {
      set((state) => {
        // Limit corpus to most recent 100 entries to prevent memory explosion
        // The backend has the full corpus - we only keep recent ones for UI
        const MAX_CORPUS_ENTRIES = 100;
        const newCorpus = [...state.corpus, entry];
        if (newCorpus.length > MAX_CORPUS_ENTRIES) {
          // Remove oldest entries (keep most recent)
          return { corpus: newCorpus.slice(-MAX_CORPUS_ENTRIES) };
        }
        return { corpus: newCorpus };
      });
    },

    updateTest: (testId, updates) => {
      set((state) => ({
        tests: state.tests.map((t) =>
          t.id === testId ? { ...t, ...updates } : t
        ),
      }));
    },

    // ========================================================================
    // Selection Actions
    // ========================================================================

    selectContract: (name) => set({ selectedContract: name }),
    selectSourceFile: (path) => set({ selectedSourceFile: path }),
    selectCorpusEntry: (id) => set({ selectedCorpusEntry: id, selectedTest: null }),
    selectTest: (id) => set({ selectedTest: id, selectedCorpusEntry: null }),
    highlightPc: (pc) => set({ highlightedPc: pc }),
    highlightLine: (line) => set({ highlightedLine: line }),

    // ========================================================================
    // Utility Methods
    // ========================================================================

    getContractByName: (name) => {
      return get().contracts.find((c) => c.name === name);
    },

    getCachedContractDetails: (name) => {
      return get().contractDetails.get(name);
    },

    cacheContractDetails: (name, details) => {
      set((state) => {
        const newMap = new Map(state.contractDetails);
        newMap.set(name, details);
        return { contractDetails: newMap };
      });
    },

    getCachedSourceFile: (path) => {
      return get().sourceFileContents.get(path);
    },

    cacheSourceFile: (path, file) => {
      set((state) => {
        const newMap = new Map(state.sourceFileContents);
        newMap.set(path, file);
        return { sourceFileContents: newMap };
      });
    },

    getCoverageForContract: (codehash) => {
      return get().coverage.runtime.get(codehash) ?? new Set();
    },

    isRevertHotspot: (codehash, pc) => {
      return get().revertHotspots.some(
        (h) => h.codehash === codehash && h.pc === pc
      );
    },

    getLineCoverageForFile: (path) => {
      return get().sourceLineCoverage.get(path);
    },

    getPcToSourceMapping: (codehash) => {
      return get().pcMappings.get(codehash);
    },

    reset: () => {
      set({
        connected: false,
        connecting: false,
        error: null,
        campaignState: 'idle' as CampaignState,
        contracts: [],
        sourceFiles: [],
        config: null,
        workerInfo: [],
        contractDetails: new Map(),
        sourceFileContents: new Map(),
        coverage: initialCoverageState,
        workers: [],
        corpus: [],
        tests: [],
        revertHotspots: [],
        sourceLineCoverage: new Map(),
        pcMappings: new Map(),
        stats: initialStats,
        selectedContract: null,
        selectedSourceFile: null,
        selectedCorpusEntry: null,
        selectedTest: null,
        highlightedPc: null,
        highlightedLine: null,
      });
    },

    // Campaign state actions
    setCampaignState: (state) => set({ campaignState: state }),
  }))
);

// ============================================================================
// Selectors (for optimized re-renders)
// ============================================================================

export const selectConnected = (state: FuzzerState) => state.connected;
export const selectContracts = (state: FuzzerState) => state.contracts;
export const selectSelectedContractSummary = (state: FuzzerState) =>
  state.contracts.find((c) => c.name === state.selectedContract);
export const selectSourceFiles = (state: FuzzerState) => state.sourceFiles;
export const selectSelectedSourceFileSummary = (state: FuzzerState) =>
  state.sourceFiles.find((f) => f.path === state.selectedSourceFile);
export const selectCorpus = (state: FuzzerState) => state.corpus;
export const selectTests = (state: FuzzerState) => state.tests;
export const selectWorkers = (state: FuzzerState) => state.workers;
export const selectStats = (state: FuzzerState) => state.stats;
export const selectRevertHotspots = (state: FuzzerState) => state.revertHotspots;
export const selectCampaignState = (state: FuzzerState) => state.campaignState;

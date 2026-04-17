'use client';

import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { useFuzzerStore } from '@/stores/fuzzerStore';
import { Panel, PanelHeader, PanelContent } from '@/components/common/Panel';
import { buildCFGFromBytecodeAsync, initEvmole, isEdgeCovered } from '@/lib/cfgBuilder';
import CFGNode, { CFGNodeData } from './CFGNode';
import { cn } from '@/lib/utils';
import { useContractDetails } from '@/hooks/useContractDetails';
import type { CFG, CFGBlock, RevertHotspot } from '@/types';

const nodeTypes = { cfgBlock: CFGNode } as const;

/**
 * Hook that subscribes to coverage for a SPECIFIC contract only.
 * Only triggers re-render when coverage size actually changes for this contract.
 * Uses Zustand's subscribeWithSelector for efficient updates.
 */
function useCoverageForContract(codehash: string | undefined) {
  const [coveredPcs, setCoveredPcs] = useState<Set<number>>(() => new Set());
  const prevSizeRef = useRef(0);

  useEffect(() => {
    if (!codehash) {
      if (prevSizeRef.current > 0) {
        setCoveredPcs(new Set());
        prevSizeRef.current = 0;
      }
      return;
    }

    // Get initial value
    const initialPcs = useFuzzerStore.getState().coverage.runtime.get(codehash);
    const initialSize = initialPcs?.size ?? 0;
    prevSizeRef.current = initialSize;
    setCoveredPcs(initialPcs ?? new Set());

    // Subscribe with selector - only fires when coverage.runtime changes
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => state.coverage.runtime.get(codehash)?.size ?? 0,
      (currentSize) => {
        if (currentSize !== prevSizeRef.current) {
          prevSizeRef.current = currentSize;
          const pcs = useFuzzerStore.getState().coverage.runtime.get(codehash);
          setCoveredPcs(pcs ?? new Set());
        }
      }
    );

    return unsubscribe;
  }, [codehash]);

  return coveredPcs;
}

/**
 * Hook that subscribes to revert hotspots for a SPECIFIC contract only.
 * Only triggers re-render when hotspots actually change for this contract.
 */
function useHotspotsForContract(codehash: string | undefined) {
  const [hotspotMap, setHotspotMap] = useState<Map<number, number>>(() => new Map());
  const prevCountRef = useRef(0);

  useEffect(() => {
    if (!codehash) {
      if (hotspotMap.size > 0) {
        setHotspotMap(new Map());
        prevCountRef.current = 0;
      }
      return;
    }

    const computeHotspots = (hotspots: RevertHotspot[]) => {
      const map = new Map<number, number>();
      let totalCount = 0;
      for (const h of hotspots) {
        if (h.codehash === codehash) {
          map.set(h.pc, h.count);
          totalCount += h.count;
        }
      }
      return { map, totalCount };
    };

    // Get initial value
    const initial = computeHotspots(useFuzzerStore.getState().revertHotspots);
    prevCountRef.current = initial.totalCount;
    setHotspotMap(initial.map);

    // Subscribe - use total count as a simple change detector
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => {
        let total = 0;
        for (const h of state.revertHotspots) {
          if (h.codehash === codehash) total += h.count;
        }
        return total;
      },
      (totalCount) => {
        if (totalCount !== prevCountRef.current) {
          prevCountRef.current = totalCount;
          const result = computeHotspots(useFuzzerStore.getState().revertHotspots);
          setHotspotMap(result.map);
        }
      }
    );

    return unsubscribe;
  }, [codehash]);

  return hotspotMap;
}

// Layout constants (similar to evmole)
const BLOCK_WIDTH = 180;
const BLOCK_HEIGHT_BASE = 40;
const BLOCK_HEIGHT_PER_INST = 16;
const HORIZONTAL_GAP = 60;
const VERTICAL_GAP = 40;

function CFGView() {
  // Only subscribe to contract selection - this rarely changes
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const contracts = useFuzzerStore((s) => s.contracts);

  // These are actions, not state - they don't cause re-renders
  const highlightPc = useFuzzerStore((s) => s.highlightPc);

  // Local UI state
  const [highlightedPc, setHighlightedPc] = useState<number | null>(null);
  const [evmoleReady, setEvmoleReady] = useState(false);
  const [cfg, setCfg] = useState<CFG | null>(null);
  const [cfgError, setCfgError] = useState<string | null>(null);

  // Initialize evmole on mount (only once)
  useEffect(() => {
    let mounted = true;
    initEvmole().then((ready) => {
      if (mounted) {
        setEvmoleReady(ready);
        console.log('[CFG] Evmole initialized:', ready);
      }
    });
    return () => { mounted = false; };
  }, []);

  // Subscribe to highlightedPc changes only (using subscribeWithSelector)
  useEffect(() => {
    // Get initial value
    setHighlightedPc(useFuzzerStore.getState().highlightedPc);

    // Subscribe with selector
    const unsubscribe = useFuzzerStore.subscribe(
      (state) => state.highlightedPc,
      (pc) => setHighlightedPc(pc)
    );
    return unsubscribe;
  }, []);

  // Get summary for codehash (memoized to avoid recalculation)
  const contractSummary = useMemo(
    () => contracts.find((c) => c.name === selectedContract),
    [contracts, selectedContract]
  );

  // Get full details for bytecode (lazy loaded)
  const contract = useContractDetails(selectedContract);

  // Use optimized hooks that only update when data actually changes for THIS contract
  const coveredPcs = useCoverageForContract(contractSummary?.codehash);
  const hotspotPcs = useHotspotsForContract(contractSummary?.codehash);

  // Build CFG from bytecode (async to allow evmole to load)
  useEffect(() => {
    if (!contract?.deployedBytecodeHex) {
      setCfg(null);
      return;
    }

    setCfgError(null);
    console.log('[CFG] Building CFG for', contract.name, 'bytecode length:', contract.deployedBytecodeHex.length);

    buildCFGFromBytecodeAsync(contract.deployedBytecodeHex)
      .then((result) => {
        console.log('[CFG] Built', result.blocks.length, 'blocks,', result.edges.length, 'edges');
        setCfg(result);
      })
      .catch((e) => {
        console.error('[CFG] Failed to build CFG:', e);
        setCfgError(e.message || 'Failed to build CFG');
      });
  }, [contract?.deployedBytecodeHex, contract?.name, evmoleReady]);

  // Calculate hierarchical layout positions
  const layoutPositions = useMemo(() => {
    if (!cfg) return new Map<number, { x: number; y: number }>();

    const positions = new Map<number, { x: number; y: number }>();
    const blocksByDepth = new Map<number, CFGBlock[]>();

    // Group blocks by depth
    for (const block of cfg.blocks) {
      const depth = block.depth ?? 0;
      if (!blocksByDepth.has(depth)) {
        blocksByDepth.set(depth, []);
      }
      blocksByDepth.get(depth)!.push(block);
    }

    // Position blocks at each depth level
    const maxDepth = Math.max(...Array.from(blocksByDepth.keys()), 0);
    let maxWidth = 0;

    for (let depth = 0; depth <= maxDepth; depth++) {
      const blocksAtDepth = blocksByDepth.get(depth) ?? [];
      const levelWidth = blocksAtDepth.length * (BLOCK_WIDTH + HORIZONTAL_GAP);
      maxWidth = Math.max(maxWidth, levelWidth);
    }

    for (let depth = 0; depth <= maxDepth; depth++) {
      const blocksAtDepth = blocksByDepth.get(depth) ?? [];
      const levelWidth = blocksAtDepth.length * (BLOCK_WIDTH + HORIZONTAL_GAP);
      const startX = (maxWidth - levelWidth) / 2;

      // Calculate Y based on accumulated heights
      let y = 0;
      for (let d = 0; d < depth; d++) {
        const blocks = blocksByDepth.get(d) ?? [];
        const maxHeight = Math.max(
          ...blocks.map(b => BLOCK_HEIGHT_BASE + b.instructions.length * BLOCK_HEIGHT_PER_INST),
          BLOCK_HEIGHT_BASE
        );
        y += maxHeight + VERTICAL_GAP;
      }

      blocksAtDepth.forEach((block, i) => {
        positions.set(block.startPc, {
          x: startX + i * (BLOCK_WIDTH + HORIZONTAL_GAP),
          y,
        });
      });
    }

    return positions;
  }, [cfg]);

  // Stable callback for PC clicks
  const handlePcClick = useCallback((pc: number) => {
    highlightPc(pc);
  }, [highlightPc]);

  // Convert CFG to react-flow nodes and edges
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    if (!cfg) return { nodes: [], edges: [] };

    // Filter out invalid blocks (missing startPc)
    const validBlocks = cfg.blocks.filter(block =>
      block && block.startPc !== undefined && block.startPc !== null
    );

    if (validBlocks.length !== cfg.blocks.length) {
      console.warn('[CFGView] Filtered out', cfg.blocks.length - validBlocks.length, 'invalid blocks');
    }

    const nodes: Node<CFGNodeData>[] = validBlocks.map((block) => {
      // Check if any PC in block is covered
      const isCovered = block.instructions.some((inst) => coveredPcs.has(inst.pc));

      // Check for revert hotspot
      const hotspotCount = block.instructions.reduce(
        (sum, inst) => sum + (hotspotPcs.get(inst.pc) ?? 0),
        0
      );

      // Check if highlighted
      const isHighlighted = block.instructions.some(
        (inst) => inst.pc === highlightedPc
      );

      const pos = layoutPositions.get(block.startPc) ?? { x: 0, y: 0 };

      return {
        id: `block-${block.startPc}`,
        type: 'cfgBlock',
        position: pos,
        data: {
          block,
          isCovered,
          hotspotCount,
          isHighlighted,
          coveredPcs,
          isEntryPoint: block.startPc === 0,
          onPcClick: handlePcClick,
        } as CFGNodeData,
      };
    });

    // Build set of valid block PCs for edge filtering
    const validBlockPcs = new Set(validBlocks.map(b => b.startPc));

    // Filter and map edges
    const validEdges = cfg.edges.filter(edge =>
      edge && edge.from !== undefined && edge.to !== undefined &&
      validBlockPcs.has(edge.from) && validBlockPcs.has(edge.to)
    );

    const edges: Edge[] = validEdges.map((edge, i) => {
      const edgeCovered = isEdgeCovered(edge, coveredPcs);

      // Edge colors: covered edges are bright, uncovered are dim
      const getEdgeColor = () => {
        if (edge.type === 'jumpi-true') {
          return edgeCovered ? '#22c55e' : '#22c55e40'; // Green, dim if uncovered
        }
        if (edge.type === 'jumpi-false') {
          return edgeCovered ? '#ef4444' : '#ef444440'; // Red, dim if uncovered
        }
        return edgeCovered ? '#6b7280' : '#6b728040'; // Gray, dim if uncovered
      };

      const color = getEdgeColor();

      return {
        id: `edge-${edge.from}-${edge.to}-${i}`,
        source: `block-${edge.from}`,
        target: `block-${edge.to}`,
        type: 'smoothstep',
        animated: false,
        style: {
          stroke: color,
          strokeWidth: edgeCovered ? 2 : 1,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color,
          width: 15,
          height: 15,
        },
      };
    });

    return { nodes, edges };
  }, [cfg, coveredPcs, hotspotPcs, highlightedPc, handlePcClick, layoutPositions]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update nodes/edges when data changes
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // Calculate coverage stats - focus on blocks, not individual PCs
  const coverageStats = useMemo(() => {
    if (!cfg) return { covered: 0, total: 0, blocksTotal: 0, blocksCovered: 0 };

    const blocksTotal = cfg.blocks.length;
    const blocksCovered = cfg.blocks.filter(block =>
      block.instructions.some(inst => coveredPcs.has(inst.pc))
    ).length;

    // Also count total/covered instructions
    const total = cfg.blocks.reduce((sum, block) => sum + block.instructions.length, 0);
    const covered = cfg.blocks.reduce(
      (sum, block) => sum + block.instructions.filter((inst) => coveredPcs.has(inst.pc)).length,
      0
    );

    return { covered, total, blocksTotal, blocksCovered };
  }, [cfg, coveredPcs]);

  if (!contract) {
    return (
      <Panel title="CFG">
        <PanelContent>
          <div className="flex items-center justify-center h-full text-sm text-zinc-500">
            {!evmoleReady ? 'Loading analyzer...' : 'Select a contract to view its CFG'}
          </div>
        </PanelContent>
      </Panel>
    );
  }

  if (cfgError) {
    return (
      <Panel title="CFG">
        <PanelContent>
          <div className="flex items-center justify-center h-full text-sm text-red-400">
            {cfgError}
          </div>
        </PanelContent>
      </Panel>
    );
  }

  if (!cfg) {
    return (
      <Panel title="CFG">
        <PanelContent>
          <div className="flex items-center justify-center h-full text-sm text-zinc-500">
            Building CFG...
          </div>
        </PanelContent>
      </Panel>
    );
  }

  return (
    <Panel>
      <PanelHeader>
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-zinc-400">Control Flow</span>
          <span className="text-xs text-zinc-500">{contract.name}</span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-zinc-500">
            {coverageStats.blocksCovered}/{coverageStats.blocksTotal} blocks
          </span>
          <span
            className={cn(
              coverageStats.blocksCovered > 0 ? 'text-green-400' : 'text-zinc-500'
            )}
          >
            {coverageStats.blocksTotal > 0
              ? ((coverageStats.blocksCovered / coverageStats.blocksTotal) * 100).toFixed(1)
              : 0}%
          </span>
        </div>
      </PanelHeader>
      <PanelContent scrollable={false} className="relative h-full min-h-0">
        <div className="absolute inset-0 w-full h-full">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.1}
            maxZoom={2}
            defaultEdgeOptions={{
              type: 'smoothstep',
            }}
          >
            <Background color="#27272a" gap={20} size={1} />
            <Controls
              showZoom
              showFitView
              showInteractive={false}
              className="bg-zinc-800 border border-zinc-700 rounded"
            />
            <MiniMap
              nodeColor={(node: Node) => {
                const data = node.data as unknown as CFGNodeData;
                if (data?.hotspotCount > 0) return '#ef4444';
                if (data?.isCovered) return '#22c55e';
                return '#3f3f46';
              }}
              maskColor="rgba(0, 0, 0, 0.8)"
              className="bg-zinc-900 border border-zinc-700 rounded"
            />
          </ReactFlow>
        </div>
      </PanelContent>
    </Panel>
  );
}

// Memoize to prevent unnecessary re-renders
export default memo(CFGView);

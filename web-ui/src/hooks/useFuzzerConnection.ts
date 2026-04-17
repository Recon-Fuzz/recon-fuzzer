/**
 * WebSocket connection hook for communicating with the fuzzer backend
 */

import { useCallback, useEffect, useRef } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import type { ServerMessage, ClientMessage, ContractInfo, SourceFile, TxTraceResult } from '@/types';

// Pending request callbacks for request-response pattern
const pendingRequests = new Map<number, {
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}>();

const RECONNECT_DELAY = 2000;
const MAX_RECONNECT_ATTEMPTS = 10;

// Global WebSocket reference for sharing across hooks
const globalWsRef = { current: null as WebSocket | null };

interface UseFuzzerConnectionOptions {
  url?: string;
  autoConnect?: boolean;
}

interface UseFuzzerConnectionReturn {
  connect: (url?: string) => void;
  disconnect: () => void;
  send: (message: ClientMessage) => void;
  connected: boolean;
  connecting: boolean;
  error: string | null;
}

// Resolve WebSocket URLs based on page protocol and optional hash fragment.
//
// Hash fragment overrides the host:port:
//   #10.10.10.10:4444  → tries ws then wss to that host
//   #wss://tunnel.com  → wss://tunnel.com/ws (explicit protocol)
//
// Default (no hash): ws://localhost:4444/ws, fallback wss://localhost:4445/ws
//
const WS_PORT = 4444;
const WSS_PORT = 4445;

/** Returns [primary, fallback] URLs to try in order */
const getWsUrls = (): [string, string | null] => {
  if (typeof window === 'undefined') {
    return [`ws://localhost:${WS_PORT}/ws`, null];
  }

  const hash = window.location.hash.replace('#', '').trim();

  // Hash with explicit protocol — use as-is, no fallback
  if (hash && (hash.startsWith('ws://') || hash.startsWith('wss://'))) {
    const url = hash.endsWith('/ws') ? hash : `${hash}/ws`;
    return [url, null];
  }

  // Hash with host:port — try ws first, fallback to wss
  if (hash) {
    return [`ws://${hash}/ws`, `wss://${hash}/ws`];
  }

  // Default: try plain ws to :4444 first (works in Chrome/Firefox from HTTPS for localhost),
  // fallback to wss on :4445 (self-signed TLS)
  return [`ws://localhost:${WS_PORT}/ws`, `wss://localhost:${WSS_PORT}/ws`];
};

export function useFuzzerConnection(
  options: UseFuzzerConnectionOptions = {}
): UseFuzzerConnectionReturn {
  const {
    autoConnect = true,
  } = options;

  // Use the global WebSocket ref so useCommands can access it
  const wsRef = globalWsRef;
  const reconnectAttempts = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connected = useFuzzerStore((s) => s.connected);
  const connecting = useFuzzerStore((s) => s.connecting);
  const error = useFuzzerStore((s) => s.error);

  const setConnected = useFuzzerStore((s) => s.setConnected);
  const setConnecting = useFuzzerStore((s) => s.setConnecting);
  const setError = useFuzzerStore((s) => s.setError);
  const handleInit = useFuzzerStore((s) => s.handleInit);
  const handleStateUpdate = useFuzzerStore((s) => s.handleStateUpdate);
  const addCorpusEntry = useFuzzerStore((s) => s.addCorpusEntry);
  const updateTest = useFuzzerStore((s) => s.updateTest);
  const setCampaignState = useFuzzerStore((s) => s.setCampaignState);
  const reset = useFuzzerStore((s) => s.reset);

  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const message: ServerMessage = JSON.parse(event.data);

        switch (message.type) {
          case 'init':
            handleInit(message);
            break;

          case 'stateUpdate':
            handleStateUpdate(message);
            break;

          case 'newCoverage':
            // Coverage is already included in stateUpdate, but we could
            // trigger additional UI effects here (e.g., highlight animation)
            console.log(
              `[Coverage] Worker ${message.workerId}: +${message.newInstructions} instructions`
            );
            break;

          case 'newCorpusEntry':
            addCorpusEntry(message);
            break;

          case 'testStateChanged':
            updateTest(message.id, {
              state: message.state,
              value: message.value ?? undefined,
              failureSequence: message.failureSequence ?? undefined,
              failureSequenceJson: message.failureSequenceJson ?? undefined,
            });
            break;

          case 'campaignStateChanged':
            setCampaignState(message.state);
            if (message.message) {
              console.log(`[Campaign] ${message.message}`);
            }
            break;

          case 'workerMessage':
            console.log(`[Worker ${message.workerId}] ${message.message}`);
            break;

          case 'commandResult':
            if (!message.success) {
              console.error(`Command ${message.id} failed: ${message.message}`);
            } else {
              console.log(`Command ${message.id} succeeded: ${message.message}`);
            }
            // Resolve pending request if any
            {
              const pending = pendingRequests.get(message.id);
              if (pending) {
                pending.resolve({ success: message.success, message: message.message });
                pendingRequests.delete(message.id);
              }
            }
            break;

          case 'contractDetails':
            // Resolve pending request with contract details
            {
              const pending = pendingRequests.get(message.id);
              if (pending) {
                pending.resolve(message.contract);
                pendingRequests.delete(message.id);
              }
            }
            break;

          case 'sourceFileContent':
            // Resolve pending request with source file content
            {
              const pending = pendingRequests.get(message.id);
              if (pending) {
                pending.resolve(message.file);
                pendingRequests.delete(message.id);
              }
            }
            break;

          case 'replayResult':
            // Resolve pending request with replay traces
            {
              const pending = pendingRequests.get(message.id);
              if (pending) {
                if (message.success) {
                  pending.resolve({ success: true, traces: message.traces });
                } else {
                  pending.resolve({ success: false, error: message.error });
                }
                pendingRequests.delete(message.id);
              }
            }
            break;

          case 'error':
            console.error(`Server error: ${message.message}`);
            setError(message.message);
            break;

          default:
            console.warn('Unknown message type:', message);
        }
      } catch (e) {
        console.error('Failed to parse message:', e);
      }
    },
    [handleInit, handleStateUpdate, addCorpusEntry, updateTest, setCampaignState, setError]
  );

  const connectToUrl = useCallback(
    (wsUrl: string, fallbackUrl: string | null) => {
      // Clean up existing connection
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      setConnecting(true);
      setError(null);

      console.log(`[WS] Trying ${wsUrl}${fallbackUrl ? ` (fallback: ${fallbackUrl})` : ''}`);

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          console.log(`[WS] Connected to ${wsUrl}`);
          setConnected(true);
          reconnectAttempts.current = 0;
        };

        ws.onclose = (event) => {
          console.log('WebSocket disconnected', event.code, event.reason);
          setConnected(false);

          // If this was the primary URL and we have a fallback, try it
          if (fallbackUrl && reconnectAttempts.current === 0) {
            console.log(`[WS] Primary failed, trying fallback: ${fallbackUrl}`);
            connectToUrl(fallbackUrl, null);
            return;
          }

          // Attempt reconnection if not intentionally closed
          if (
            event.code !== 1000 &&
            reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS
          ) {
            reconnectAttempts.current++;
            const delay = RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts.current - 1);
            console.log(
              `Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current}/${MAX_RECONNECT_ATTEMPTS})`
            );

            reconnectTimeoutRef.current = setTimeout(() => {
              // On reconnect, try the full chain again
              const [primary, fb] = getWsUrls();
              connectToUrl(primary, fb);
            }, delay);
          }
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setError('Connection error');
        };

        ws.onmessage = handleMessage;
      } catch (e) {
        console.error('Failed to create WebSocket:', e);
        // If constructor threw and we have a fallback, try it
        if (fallbackUrl) {
          console.log(`[WS] Constructor failed, trying fallback: ${fallbackUrl}`);
          connectToUrl(fallbackUrl, null);
          return;
        }
        setError('Failed to connect');
        setConnecting(false);
      }
    },
    [handleMessage, setConnected, setConnecting, setError]
  );

  const connect = useCallback(
    (url?: string) => {
      if (url) {
        connectToUrl(url, null);
      } else {
        const [primary, fallback] = getWsUrls();
        connectToUrl(primary, fallback);
      }
    },
    [connectToUrl]
  );

  const disconnect = useCallback(() => {
    // Clear reconnect timeout
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    // Close WebSocket
    if (wsRef.current) {
      wsRef.current.close(1000, 'User disconnected');
      wsRef.current = null;
    }

    reset();
  }, [reset]);

  const send = useCallback((message: ClientMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    connect,
    disconnect,
    send,
    connected,
    connecting,
    error,
  };
}

/**
 * Hook for sending commands to the fuzzer
 * Note: This hook does NOT create a new WebSocket connection - it uses a global sender
 */
export function useCommands() {
  const connected = useFuzzerStore((s) => s.connected);
  const commandIdRef = useRef(0);

  // Get the global send function from the singleton connection
  const send = useCallback((message: ClientMessage) => {
    const ws = globalWsRef.current;
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }, []);

  const getNextId = useCallback(() => {
    return ++commandIdRef.current;
  }, []);

  const injectDictionary = useCallback(
    (values: string[], broadcast = false) => {
      if (!connected) return;
      send({
        type: 'injectDictionary',
        id: getNextId(),
        values,
        broadcast,
      });
    },
    [connected, send, getNextId]
  );

  const injectSequence = useCallback(
    (sequence: { function: string; args: string[]; sender?: string; value?: string; target?: string }[]) => {
      if (!connected) return;
      send({
        type: 'injectSequence',
        id: getNextId(),
        sequence,
      });
    },
    [connected, send, getNextId]
  );

  const clampArgument = useCallback(
    (functionName: string, paramIdx: number, value: string) => {
      if (!connected) return;
      send({
        type: 'clampArgument',
        id: getNextId(),
        function: functionName,
        paramIdx,
        value,
      });
    },
    [connected, send, getNextId]
  );

  const unclampArgument = useCallback(
    (functionName: string, paramIdx: number) => {
      if (!connected) return;
      send({
        type: 'unclampArgument',
        id: getNextId(),
        function: functionName,
        paramIdx,
      });
    },
    [connected, send, getNextId]
  );

  const clearClamps = useCallback(() => {
    if (!connected) return;
    send({
      type: 'clearAllClamps',
      id: getNextId(),
    });
  }, [connected, send, getNextId]);

  const solveBranch = useCallback(
    (codehash: string, pc: number) => {
      if (!connected) return;
      send({
        type: 'solveBranch',
        id: getNextId(),
        codehash,
        pc,
      });
    },
    [connected, send, getNextId]
  );

  const setTargetFunctions = useCallback(
    (functions: string[]) => {
      if (!connected) return;
      send({
        type: 'setTargetFunctions',
        id: getNextId(),
        functions,
      });
    },
    [connected, send, getNextId]
  );

  const queryLlm = useCallback(
    (prompt: string, options: { includeCoverage?: boolean; includeCorpus?: boolean; includeStruggling?: boolean; customContext?: string } = {}) => {
      if (!connected) return;
      send({
        type: 'llmQuery',
        id: getNextId(),
        prompt,
        context: {
          includeCoverage: options.includeCoverage ?? true,
          includeCorpus: options.includeCorpus ?? true,
          includeStruggling: options.includeStruggling ?? true,
          customContext: options.customContext,
        },
      });
    },
    [connected, send, getNextId]
  );

  const injectFuzzTransactions = useCallback(
    (template: string, priority = 1) => {
      if (!connected) return;
      send({
        type: 'injectFuzzTransactions',
        id: getNextId(),
        template,
        priority,
      });
    },
    [connected, send, getNextId]
  );

  const clearFuzzTemplates = useCallback(() => {
    if (!connected) return;
    send({
      type: 'clearFuzzTemplates',
      id: getNextId(),
    });
  }, [connected, send, getNextId]);

  const getContractDetails = useCallback(
    (contractName: string): Promise<ContractInfo | null> => {
      if (!connected) return Promise.resolve(null);

      const id = getNextId();
      return new Promise((resolve) => {
        pendingRequests.set(id, {
          resolve: (value) => resolve(value as ContractInfo | null),
          reject: () => resolve(null),
        });
        send({
          type: 'getContractDetails',
          id,
          contractName,
        });

        // Timeout after 10 seconds
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            resolve(null);
          }
        }, 10000);
      });
    },
    [connected, send, getNextId]
  );

  const getSourceFile = useCallback(
    (path: string): Promise<SourceFile | null> => {
      if (!connected) return Promise.resolve(null);

      const id = getNextId();
      return new Promise((resolve) => {
        pendingRequests.set(id, {
          resolve: (value) => resolve(value as SourceFile | null),
          reject: () => resolve(null),
        });
        send({
          type: 'getSourceFile',
          id,
          path,
        });

        // Timeout after 10 seconds
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            resolve(null);
          }
        }, 10000);
      });
    },
    [connected, send, getNextId]
  );

  /**
   * Replay a transaction sequence and get execution traces
   * @param sequenceJson - Raw JSON serialized sequence (same format as corpus files)
   */
  const replaySequence = useCallback(
    (sequenceJson: string): Promise<{ success: boolean; traces?: TxTraceResult[]; error?: string }> => {
      if (!connected) return Promise.resolve({ success: false, error: 'Not connected' });
      if (!sequenceJson || sequenceJson.length === 0) {
        return Promise.resolve({ success: false, error: 'No sequence JSON provided' });
      }

      const id = getNextId();

      return new Promise((resolve) => {
        pendingRequests.set(id, {
          resolve: (value) => resolve(value as { success: boolean; traces?: TxTraceResult[]; error?: string }),
          reject: () => resolve({ success: false, error: 'Request failed' }),
        });

        const msg = {
          type: 'replaySequence' as const,
          id,
          sequenceJson,
        };
        // Debug: log exactly what we're sending
        console.log('[Replay] Sending:', JSON.stringify(msg).substring(0, 200) + '...');
        send(msg);

        // Timeout after 5 minutes (replay with tracing can be very slow for large sequences)
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            resolve({ success: false, error: 'Timeout - replay took too long' });
          }
        }, 300000);
      });
    },
    [connected, send, getNextId]
  );

  return {
    connected,
    injectDictionary,
    injectSequence,
    clampArgument,
    unclampArgument,
    clearClamps,
    solveBranch,
    setTargetFunctions,
    queryLlm,
    injectFuzzTransactions,
    clearFuzzTemplates,
    getContractDetails,
    getSourceFile,
    replaySequence,
  };
}

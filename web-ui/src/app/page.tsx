'use client';

import { useState, useEffect } from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { useFuzzerConnection } from '@/hooks/useFuzzerConnection';
import { useFuzzerStore } from '@/stores/fuzzerStore';

import TopBar from '@/components/layout/TopBar';
import Sidebar from '@/components/layout/Sidebar';
import BottomPanel from '@/components/layout/BottomPanel';
import { CoveragePanel } from '@/components/coverage';
import InteractivePanel from '@/components/interactive/InteractivePanel';

export default function Home() {
  const { connect, connected, connecting, error } = useFuzzerConnection({
    autoConnect: false,
  });

  const [bottomExpanded, setBottomExpanded] = useState(true);

  // Connect on mount — uses the resolved URL from query params / localStorage / default
  useEffect(() => {
    connect(); // url resolved internally by getWsUrl()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty deps - connect only once on mount

  // Only show connection screen on initial load or permanent failure
  // During reconnection attempts, keep the main UI visible with a status indicator
  const hasEverConnected = useFuzzerStore((s) => s.contracts.length > 0);

  if (!connected && !connecting && !hasEverConnected) {
    return <ConnectionScreen error={error} onRetry={() => connect()} />;
  }

  return (
    <div className="h-screen w-screen flex flex-col bg-zinc-950 text-zinc-100 overflow-hidden">
      {/* Top Bar */}
      <TopBar />

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar />

        {/* Main Panel Area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <PanelGroup direction="vertical" className="flex-1">
            {/* Top Section: CFG + Source + Interactive */}
            <Panel defaultSize={75} minSize={30}>
              <PanelGroup direction="horizontal" className="h-full">
                {/* Coverage View */}
                <Panel defaultSize={65} minSize={30}>
                  <div className="h-full border-r border-zinc-800">
                    <CoveragePanel />
                  </div>
                </Panel>

                <PanelResizeHandle className="w-1 bg-zinc-800 hover:bg-blue-500 transition-colors resize-handle" />

                {/* Interactive Panel */}
                <Panel defaultSize={35} minSize={15}>
                  <InteractivePanel />
                </Panel>
              </PanelGroup>
            </Panel>

            <PanelResizeHandle className="h-1 bg-zinc-800 hover:bg-blue-500 transition-colors resize-handle" />

            {/* Bottom Panel */}
            <Panel
              defaultSize={25}
              minSize={5}
              collapsible
              collapsedSize={5}
            >
              <BottomPanel
                expanded={bottomExpanded}
                onToggle={() => setBottomExpanded(!bottomExpanded)}
              />
            </Panel>
          </PanelGroup>
        </div>
      </div>
    </div>
  );
}

interface ConnectionScreenProps {
  error: string | null;
  onRetry: () => void;
}

function ConnectionScreen({ error, onRetry }: ConnectionScreenProps) {
  return (
    <div className="h-screen w-screen flex items-center justify-center bg-zinc-950">
      <div className="text-center max-w-md p-8">
        <div className="mb-6">
          <svg
            className="w-16 h-16 mx-auto text-zinc-700"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M12 6v6m0 0v6m0-6h6m-6 0H6"
            />
          </svg>
        </div>

        <h1 className="text-2xl font-bold text-zinc-100 mb-2">
          Recon Fuzzer
        </h1>

        {error ? (
          <>
            <p className="text-red-400 mb-4">{error}</p>
            <p className="text-zinc-500 mb-6 text-sm">
              Make sure the fuzzer is running with the <code className="bg-zinc-900 px-1 rounded">--web</code> flag
            </p>
            <button
              onClick={onRetry}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium transition-colors"
            >
              Retry Connection
            </button>
          </>
        ) : (
          <>
            <p className="text-zinc-400 mb-4">
              Connecting to fuzzer...
            </p>
            <div className="flex justify-center">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          </>
        )}

        <div className="mt-8 text-xs text-zinc-600 text-left space-y-4">
          <div>
            <p className="font-medium text-zinc-500 mb-1">1. Start the fuzzer</p>
            <code className="block p-2 bg-zinc-900 rounded">
              recon fuzz ./project --web
            </code>
          </div>

          <TlsTrustStep />
        </div>
      </div>
    </div>
  );
}

/** Only renders the TLS trust instructions when page is served over HTTPS. Uses useEffect to avoid hydration mismatch. */
function TlsTrustStep() {
  const [isHttps, setIsHttps] = useState(false);
  useEffect(() => {
    setIsHttps(window.location.protocol === 'https:');
  }, []);

  if (!isHttps) return null;

  return (
    <div>
      <p className="font-medium text-zinc-500 mb-1">2. Trust the local certificate</p>
      <p className="text-zinc-600 mb-1">
        If connection fails, open this link and accept the self-signed certificate:
      </p>
      <a
        href="https://localhost:4445"
        target="_blank"
        rel="noopener noreferrer"
        className="block p-2 bg-zinc-900 rounded text-blue-400 hover:text-blue-300 transition-colors"
      >
        https://localhost:4445
      </a>
      <p className="text-zinc-600 mt-1">
        Then come back here and click retry.
      </p>
    </div>
  );
}

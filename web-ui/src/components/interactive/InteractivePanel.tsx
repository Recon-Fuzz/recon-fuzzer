'use client';

import { useState } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { useCommands } from '@/hooks/useFuzzerConnection';
import { Panel, PanelHeader, PanelContent } from '@/components/common/Panel';
import { cn } from '@/lib/utils';
import { useContractDetails } from '@/hooks/useContractDetails';
import type { FunctionInfo, ParamInfo } from '@/types';
import {
  BookOpen,
  Crosshair,
  MessageSquare,
  PlayCircle,
  Settings,
  Shuffle,
} from 'lucide-react';

type Tab = 'dictionary' | 'clamp' | 'sequence' | 'template' | 'solve' | 'llm';

export default function InteractivePanel() {
  const [activeTab, setActiveTab] = useState<Tab>('dictionary');

  return (
    <Panel>
      <PanelHeader>
        <span className="text-xs font-medium text-zinc-400">Interactive</span>
        <div className="flex items-center gap-1">
          <TabButton
            active={activeTab === 'dictionary'}
            onClick={() => setActiveTab('dictionary')}
            icon={<BookOpen className="w-3.5 h-3.5" />}
            title="Dictionary"
          />
          <TabButton
            active={activeTab === 'clamp'}
            onClick={() => setActiveTab('clamp')}
            icon={<Settings className="w-3.5 h-3.5" />}
            title="Clamp"
          />
          <TabButton
            active={activeTab === 'sequence'}
            onClick={() => setActiveTab('sequence')}
            icon={<PlayCircle className="w-3.5 h-3.5" />}
            title="Inject"
          />
          <TabButton
            active={activeTab === 'template'}
            onClick={() => setActiveTab('template')}
            icon={<Shuffle className="w-3.5 h-3.5" />}
            title="Template"
          />
          <TabButton
            active={activeTab === 'solve'}
            onClick={() => setActiveTab('solve')}
            icon={<Crosshair className="w-3.5 h-3.5" />}
            title="Solve"
          />
          <TabButton
            active={activeTab === 'llm'}
            onClick={() => setActiveTab('llm')}
            icon={<MessageSquare className="w-3.5 h-3.5" />}
            title="AI"
          />
        </div>
      </PanelHeader>
      <PanelContent>
        <div className="p-3 h-full">
          {activeTab === 'dictionary' && <DictionaryTab />}
          {activeTab === 'clamp' && <ClampTab />}
          {activeTab === 'sequence' && <SequenceTab />}
          {activeTab === 'template' && <TemplateTab />}
          {activeTab === 'solve' && <SolveTab />}
          {activeTab === 'llm' && <LlmTab />}
        </div>
      </PanelContent>
    </Panel>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  title: string;
}

function TabButton({ active, onClick, icon, title }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'p-1.5 rounded transition-colors',
        active
          ? 'bg-blue-500/20 text-blue-400'
          : 'text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300'
      )}
      title={title}
    >
      {icon}
    </button>
  );
}

function DictionaryTab() {
  const [values, setValues] = useState('');
  const [broadcast, setBroadcast] = useState(false);
  const { injectDictionary } = useCommands();

  const handleInject = () => {
    const parsed = values
      .split('\n')
      .map((v) => v.trim())
      .filter((v) => v.length > 0);

    if (parsed.length > 0) {
      injectDictionary(parsed, broadcast);
      setValues('');
    }
  };

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Add values to the fuzzer dictionary. One value per line (hex or decimal).
      </p>

      <textarea
        value={values}
        onChange={(e) => setValues(e.target.value)}
        placeholder="0x1234...&#10;1000000&#10;0xdead..."
        className="flex-1 min-h-[100px] bg-zinc-800 border border-zinc-700 rounded p-2 text-xs font-mono resize-none focus:outline-none focus:border-blue-500"
      />

      <label className="flex items-center gap-2 text-xs text-zinc-400">
        <input
          type="checkbox"
          checked={broadcast}
          onChange={(e) => setBroadcast(e.target.checked)}
          className="rounded border-zinc-600 bg-zinc-800"
        />
        Broadcast to all workers
      </label>

      <button
        onClick={handleInject}
        disabled={!values.trim()}
        className={cn(
          'py-2 rounded text-xs font-medium transition-colors',
          values.trim()
            ? 'bg-blue-600 hover:bg-blue-500 text-white'
            : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
        )}
      >
        Inject to Dictionary
      </button>
    </div>
  );
}

function ClampTab() {
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const { clampArgument, unclampArgument, clearClamps } = useCommands();

  const [selectedFunc, setSelectedFunc] = useState<string>('');
  const [clampValues, setClampValues] = useState<Map<string, string>>(new Map());

  // Lazy load full contract details for functions
  const contract = useContractDetails(selectedContract);
  const functions: FunctionInfo[] = contract?.functions.filter(
    (f: FunctionInfo) => f.stateMutability !== 'view' && f.stateMutability !== 'pure'
  ) ?? [];
  const selectedFuncInfo = functions.find((f: FunctionInfo) => f.name === selectedFunc);

  const handleClamp = (paramIdx: number, value: string) => {
    if (selectedFunc && value.trim()) {
      clampArgument(selectedFunc, paramIdx, value);
      setClampValues((prev) => {
        const next = new Map(prev);
        next.set(`${selectedFunc}:${paramIdx}`, value);
        return next;
      });
    }
  };

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Clamp function arguments to specific values for the interactive worker.
      </p>

      <select
        value={selectedFunc}
        onChange={(e) => setSelectedFunc(e.target.value)}
        className="bg-zinc-800 border border-zinc-700 rounded p-2 text-xs focus:outline-none focus:border-blue-500"
      >
        <option value="">Select function...</option>
        {functions.map((f: FunctionInfo) => (
          <option key={f.signature} value={f.name}>
            {f.name}({f.inputs.map((i: ParamInfo) => i.type).join(', ')})
          </option>
        ))}
      </select>

      {selectedFuncInfo && selectedFuncInfo.inputs.length > 0 && (
        <div className="flex-1 space-y-2 overflow-auto">
          {selectedFuncInfo.inputs.map((input: ParamInfo, idx: number) => (
            <div key={idx} className="flex items-center gap-2">
              <span className="text-xs text-zinc-500 w-20 truncate">
                {input.name || `arg${idx}`}
              </span>
              <input
                type="text"
                placeholder={input.type}
                value={clampValues.get(`${selectedFunc}:${idx}`) ?? ''}
                onChange={(e) => {
                  const val = e.target.value;
                  if (val) {
                    handleClamp(idx, val);
                  } else {
                    unclampArgument(selectedFunc, idx);
                    setClampValues((prev) => {
                      const next = new Map(prev);
                      next.delete(`${selectedFunc}:${idx}`);
                      return next;
                    });
                  }
                }}
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          ))}
        </div>
      )}

      <button
        onClick={() => {
          clearClamps();
          setClampValues(new Map());
        }}
        className="py-2 bg-zinc-700 hover:bg-zinc-600 rounded text-xs font-medium transition-colors"
      >
        Clear All Clamps
      </button>
    </div>
  );
}

function SequenceTab() {
  const selectedContract = useFuzzerStore((s) => s.selectedContract);
  const { injectSequence } = useCommands();

  const [sequence, setSequence] = useState<
    Array<{ function: string; args: string }>
  >([]);

  // Lazy load full contract details for functions
  const contract = useContractDetails(selectedContract);
  const functions: FunctionInfo[] = contract?.functions ?? [];

  const addCall = () => {
    setSequence([...sequence, { function: '', args: '' }]);
  };

  const removeCall = (idx: number) => {
    setSequence(sequence.filter((_, i) => i !== idx));
  };

  const updateCall = (idx: number, field: 'function' | 'args', value: string) => {
    setSequence(
      sequence.map((call, i) =>
        i === idx ? { ...call, [field]: value } : call
      )
    );
  };

  const handleInject = () => {
    const parsed = sequence
      .filter((call) => call.function)
      .map((call) => ({
        function: call.function,
        args: call.args.split(',').map((a) => a.trim()).filter((a) => a),
      }));

    if (parsed.length > 0) {
      injectSequence(parsed);
      setSequence([]);
    }
  };

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Build and inject a custom call sequence.
      </p>

      <div className="flex-1 space-y-2 overflow-auto">
        {sequence.map((call, idx) => (
          <div key={idx} className="flex items-center gap-2 p-2 bg-zinc-800/50 rounded">
            <span className="text-xs text-zinc-600">{idx + 1}.</span>
            <select
              value={call.function}
              onChange={(e) => updateCall(idx, 'function', e.target.value)}
              className="flex-1 bg-zinc-800 border border-zinc-700 rounded p-1 text-xs"
            >
              <option value="">Select function...</option>
              {functions.map((f: FunctionInfo) => (
                <option key={f.signature} value={f.name}>
                  {f.name}
                </option>
              ))}
            </select>
            <input
              type="text"
              placeholder="args (comma-separated)"
              value={call.args}
              onChange={(e) => updateCall(idx, 'args', e.target.value)}
              className="w-32 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono"
            />
            <button
              onClick={() => removeCall(idx)}
              className="text-zinc-500 hover:text-red-400"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <button
          onClick={addCall}
          className="flex-1 py-2 bg-zinc-700 hover:bg-zinc-600 rounded text-xs font-medium transition-colors"
        >
          + Add Call
        </button>
        <button
          onClick={handleInject}
          disabled={sequence.length === 0}
          className={cn(
            'flex-1 py-2 rounded text-xs font-medium transition-colors',
            sequence.length > 0
              ? 'bg-blue-600 hover:bg-blue-500 text-white'
              : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
          )}
        >
          Inject Sequence
        </button>
      </div>
    </div>
  );
}

function TemplateTab() {
  const [template, setTemplate] = useState('');
  const [priority, setPriority] = useState(1);
  const [templates, setTemplates] = useState<Array<{ template: string; priority: number }>>([]);
  const { injectFuzzTransactions, clearFuzzTemplates } = useCommands();

  const handleAdd = () => {
    if (!template.trim()) return;
    injectFuzzTransactions(template, priority);
    setTemplates([...templates, { template, priority }]);
    setTemplate('');
  };

  const handleClearAll = () => {
    clearFuzzTemplates();
    setTemplates([]);
  };

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Define transaction templates with wildcards. Use <code className="bg-zinc-800 px-1 rounded">?</code> for
        fuzzed values and concrete values for fixed args.
      </p>

      <div className="space-y-2">
        <input
          type="text"
          value={template}
          onChange={(e) => setTemplate(e.target.value)}
          placeholder="f(1,?,?) ; g(?,2,5)"
          className="w-full bg-zinc-800 border border-zinc-700 rounded p-2 text-xs font-mono focus:outline-none focus:border-blue-500"
        />

        <div className="flex items-center gap-2">
          <label className="text-xs text-zinc-500">Priority:</label>
          <input
            type="number"
            min={1}
            max={100}
            value={priority}
            onChange={(e) => setPriority(Math.max(1, parseInt(e.target.value) || 1))}
            className="w-16 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
          />
          <span className="text-[10px] text-zinc-600 flex-1">
            Higher = more likely to be selected
          </span>
        </div>
      </div>

      {templates.length > 0 && (
        <div className="flex-1 overflow-auto space-y-1">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wide">Active Templates</div>
          {templates.map((t, idx) => (
            <div
              key={idx}
              className="p-2 bg-zinc-800/50 rounded text-xs font-mono flex items-center justify-between"
            >
              <span className="text-zinc-300 truncate flex-1">{t.template}</span>
              <span className="text-zinc-500 ml-2">p={t.priority}</span>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={handleAdd}
          disabled={!template.trim()}
          className={cn(
            'flex-1 py-2 rounded text-xs font-medium transition-colors',
            template.trim()
              ? 'bg-blue-600 hover:bg-blue-500 text-white'
              : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
          )}
        >
          Add Template
        </button>
        <button
          onClick={handleClearAll}
          disabled={templates.length === 0}
          className={cn(
            'py-2 px-3 rounded text-xs font-medium transition-colors',
            templates.length > 0
              ? 'bg-zinc-700 hover:bg-zinc-600'
              : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
          )}
        >
          Clear All
        </button>
      </div>

      <div className="text-[10px] text-zinc-600 space-y-1">
        <div><strong>Format:</strong> function(arg1,arg2,...) ; function2(...)</div>
        <div><strong>Example:</strong> transfer(?,1000) ; approve(0xdead...,?)</div>
      </div>
    </div>
  );
}

function SolveTab() {
  const revertHotspots = useFuzzerStore((s) => s.revertHotspots);
  const { solveBranch } = useCommands();

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Request concolic solving for a specific branch. Click on a revert hotspot
        to try solving the constraint.
      </p>

      <div className="flex-1 overflow-auto">
        {revertHotspots.length === 0 ? (
          <div className="text-center text-xs text-zinc-600 py-4">
            No revert hotspots detected yet
          </div>
        ) : (
          <div className="space-y-1">
            {revertHotspots.slice(0, 10).map((hotspot) => (
              <button
                key={`${hotspot.codehash}-${hotspot.pc}`}
                onClick={() => solveBranch(hotspot.codehash, hotspot.pc)}
                className="w-full p-2 bg-zinc-800/50 hover:bg-zinc-800 rounded text-left transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-zinc-400">
                    PC {hotspot.pc}
                  </span>
                  <span className="text-xs text-red-400">
                    {hotspot.count.toLocaleString()}×
                  </span>
                </div>
                {hotspot.functionName && (
                  <div className="text-xs text-zinc-500 mt-0.5">
                    {hotspot.functionName}
                  </div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      <p className="text-[10px] text-zinc-600">
        Solving will queue a concolic execution task targeting the selected branch.
      </p>
    </div>
  );
}

function LlmTab() {
  const [prompt, setPrompt] = useState('');
  const [response, setResponse] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { queryLlm } = useCommands();

  const handleQuery = async () => {
    if (!prompt.trim()) return;
    setLoading(true);
    setResponse(null);

    // Note: The actual response would come via WebSocket
    queryLlm(prompt, {
      includeCoverage: true,
      includeCorpus: true,
      includeStruggling: true,
    });

    // For now, just show a placeholder
    setTimeout(() => {
      setResponse('Query sent to LLM. Response will appear in logs.');
      setLoading(false);
    }, 500);
  };

  return (
    <div className="flex flex-col h-full gap-3">
      <p className="text-xs text-zinc-500">
        Chat with the LLM to get suggestions for improving coverage.
      </p>

      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        placeholder="Ask about uncovered branches, suggest dictionary values, or request targeted sequences..."
        className="flex-1 min-h-[80px] bg-zinc-800 border border-zinc-700 rounded p-2 text-xs resize-none focus:outline-none focus:border-blue-500"
      />

      <button
        onClick={handleQuery}
        disabled={!prompt.trim() || loading}
        className={cn(
          'py-2 rounded text-xs font-medium transition-colors',
          prompt.trim() && !loading
            ? 'bg-purple-600 hover:bg-purple-500 text-white'
            : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
        )}
      >
        {loading ? 'Sending...' : 'Send to LLM'}
      </button>

      {response && (
        <div className="p-2 bg-zinc-800/50 rounded text-xs text-zinc-400">
          {response}
        </div>
      )}
    </div>
  );
}

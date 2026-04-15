// Coordinator Worker — orchestrates N fuzzer Web Workers with SharedArrayBuffer
//
// Architecture:
//   Main Thread (index.html/app.js)
//     └─ Coordinator Web Worker (this file)
//          ├─ initSync(module) → creates shared WASM memory
//          ├─ WasmSharedFuzzer: deploy, init_shared_state()
//          └─ Spawns N Fuzzer Web Workers (fuzz-worker.js)
//               ├─ initSync({ module, memory }) → same WASM heap
//               ├─ WasmFuzzWorker: gets Arc<SharedState> from global
//               └─ run_batch() → reads/writes SharedState via RwLock
//
// All N workers + coordinator share the same WebAssembly.Memory (SharedArrayBuffer).
// wasm_safe_mutex::RwLock uses Atomics.wait/notify for cross-worker sync.

import { initSync, WasmSharedFuzzer } from '../pkg/browser_fuzzer.js';

let fuzzer = null;           // WasmSharedFuzzer (coordinator — deploy, setup, status)
let fuzzWorkers = [];        // Web Worker[] (real OS-level workers)
let numWorkers = 4;
let running = false;
let stopRequested = false;
let workersFinished = 0;

// Shared WASM module + memory for workers
let wasmModule = null;
let sharedMemory = null;

// Saved state for re-deploy
let savedArtifactsJson = null;
let savedConfigJson = null;

// Campaign timing
let startTime = 0;
let totalTestLimit = 50000;
let shrinkLimit = 5000;

// Event dedup — only report first "falsified" per test (matches main fuzzer)
let reportedFalsified = new Set();

// Status polling
const STATUS_INTERVAL_MS = 3000;
let statusInterval = null;

// =========================================================================
// Helpers
// =========================================================================

function send(type, data) {
    postMessage({ type, ...data });
}

function sendLog(msg, cls) {
    send('log', { msg, cls: cls || '' });
}

function parseResult(json) {
    try { return JSON.parse(json); }
    catch { return null; }
}

function formatTimestamp() {
    const now = new Date();
    const y = now.getFullYear();
    const mo = String(now.getMonth() + 1).padStart(2, '0');
    const d = String(now.getDate()).padStart(2, '0');
    const h = String(now.getHours()).padStart(2, '0');
    const mi = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    const cs = String(Math.floor(now.getMilliseconds() / 10)).padStart(2, '0');
    return `[${y}-${mo}-${d} ${h}:${mi}:${s}.${cs}]`;
}

// =========================================================================
// Message handler — main thread communication
// =========================================================================

onmessage = async (e) => {
    const msg = e.data;

    switch (msg.type) {
        case 'init': {
            // Guard: only init once (prevents duplicate WASM fetches on repeated calls)
            if (wasmModule) {
                send('init_done');
                break;
            }
            try {
                // Fetch + compile WASM module, then init coordinator with initSync
                const response = await fetch('../pkg/browser_fuzzer_bg.wasm');
                const wasmBytes = await response.arrayBuffer();
                wasmModule = await WebAssembly.compile(wasmBytes);

                // Init coordinator — creates shared WebAssembly.Memory (SharedArrayBuffer)
                const wasm = initSync({ module: wasmModule });
                sharedMemory = wasm.memory;

                send('init_done');
            } catch (err) {
                send('init_error', { error: err.message });
            }
            break;
        }

        case 'create_fuzzer': {
            try {
                savedConfigJson = msg.config;
                fuzzer = new WasmSharedFuzzer(msg.config);
                if (savedArtifactsJson) {
                    fuzzer.load_artifacts(savedArtifactsJson);
                }
                send('result', { method: 'create_fuzzer', data: { success: true } });
            } catch (err) {
                send('result', { method: 'create_fuzzer', data: { success: false, error: err.message } });
            }
            break;
        }

        case 'load_config': {
            if (!fuzzer) { send('result', { method: 'load_config', data: { success: false, error: 'No fuzzer' } }); break; }
            try {
                const result = parseResult(fuzzer.load_config(msg.yaml));
                send('result', { method: 'load_config', data: result });
            } catch (err) {
                send('result', { method: 'load_config', data: { success: false, error: err.message } });
            }
            break;
        }

        case 'load_artifacts': {
            if (!fuzzer) { send('result', { method: 'load_artifacts', data: { success: false, error: 'No fuzzer' } }); break; }
            try {
                savedArtifactsJson = msg.artifactsJson;
                const result = parseResult(fuzzer.load_artifacts(msg.artifactsJson));
                send('result', { method: 'load_artifacts', data: result });
            } catch (err) {
                send('result', { method: 'load_artifacts', data: { success: false, error: err.message } });
            }
            break;
        }

        case 'deploy': {
            if (!fuzzer) { send('result', { method: 'deploy', data: { success: false, error: 'No fuzzer' } }); break; }
            try {
                sendLog(`Deploying ${msg.contractName}...`);
                const result = parseResult(fuzzer.deploy(msg.contractName));
                send('result', { method: 'deploy', data: result });
            } catch (err) {
                send('result', { method: 'deploy', data: { success: false, error: err.message } });
            }
            break;
        }

        case 'set_mode': {
            if (!fuzzer) { send('result', { method: 'set_mode', data: { success: false, error: 'No fuzzer' } }); break; }
            try {
                const result = parseResult(fuzzer.set_mode(msg.mode));
                send('result', { method: 'set_mode', data: result });
            } catch (err) {
                send('result', { method: 'set_mode', data: { success: false, error: err.message } });
            }
            break;
        }

        case 'start_fuzzing': {
            if (!fuzzer || running) break;
            numWorkers = msg.numWorkers || 4;
            running = true;
            stopRequested = false;
            runCampaign();
            break;
        }

        case 'stop': {
            stopRequested = true;
            if (fuzzer) {
                fuzzer.stop();  // Sets shared running=false, all workers see it
            }
            break;
        }
    }
};

// =========================================================================
// Start fuzzing — init SharedState, spawn N real Web Workers
// =========================================================================

async function runCampaign() {
    send('fuzzing_started');
    startTime = Date.now();
    reportedFalsified = new Set();
    workersFinished = 0;

    // Step 1: Initialize SharedState (tests, coverage, codehash_map → RwLock)
    sendLog('Initializing shared state...');
    try {
        const result = parseResult(fuzzer.init_shared_state());
        if (!result || !result.success) {
            sendLog(`SharedState init failed: ${result?.error || 'unknown'}`, 'error');
            running = false;
            send('fuzzing_done', { finalResults: '', wasStopped: false });
            return;
        }
        sendLog(`SharedState: ${result.tests} tests initialized`);
    } catch (err) {
        sendLog(`SharedState error: ${err.message}`, 'error');
        running = false;
        send('fuzzing_done', { finalResults: '', wasStopped: false });
        return;
    }

    // Step 2: Export EVM state (each worker creates its own EVM copy)
    let exportedState;
    try {
        exportedState = fuzzer.export_state();
        const parsed = parseResult(exportedState);
        if (parsed?.error) {
            sendLog(`Export failed: ${parsed.error}`, 'error');
            running = false;
            send('fuzzing_done', { finalResults: '', wasStopped: false });
            return;
        }
        totalTestLimit = parsed?.config?.test_limit || 50000;
        shrinkLimit = parsed?.config?.shrink_limit || 5000;
    } catch (err) {
        sendLog(`Export error: ${err.message}`, 'error');
        running = false;
        send('fuzzing_done', { finalResults: '', wasStopped: false });
        return;
    }

    // Step 3: Prepare per-worker state (split test limit across workers)
    const baseSeed = parseResult(exportedState)?.config?.seed || Date.now();
    const perWorkerLimit = Math.ceil(totalTestLimit / numWorkers);
    const modifiedState = JSON.parse(exportedState);
    modifiedState.config.test_limit = perWorkerLimit;
    const modifiedStateJson = JSON.stringify(modifiedState);

    // Step 4: Spawn N real Web Workers — each runs on its own CPU core
    sendLog(`Spawning ${numWorkers} Web Workers (shared memory)...`, 'success');
    fuzzWorkers = [];

    for (let i = 0; i < numWorkers; i++) {
        try {
            const w = new Worker('fuzz-worker.js', { type: 'module' });

            w.onmessage = (e) => handleWorkerMessage(i, e.data);
            w.onerror = (e) => {
                sendLog(`${formatTimestamp()} [Worker ${i}] Error: ${e.message}`, 'error');
                workerDone(i);
            };

            // Send shared module + memory + state to worker
            w.postMessage({
                module: wasmModule,
                memory: sharedMemory,
                state: modifiedStateJson,
                workerId: i,
                seed: baseSeed,
            });

            fuzzWorkers.push(w);
            sendLog(`${formatTimestamp()} [Worker ${i}] Spawned`);
        } catch (err) {
            sendLog(`${formatTimestamp()} [Worker ${i}] Spawn error: ${err.message}`, 'error');
        }
    }

    if (fuzzWorkers.length === 0) {
        sendLog('No workers spawned', 'error');
        running = false;
        send('fuzzing_done', { finalResults: '', wasStopped: false });
        return;
    }

    sendLog(`${fuzzWorkers.length} workers running on separate cores`, 'success');

    // Step 5: Start status polling (reads SharedState via coordinator's WASM instance)
    statusInterval = setInterval(printStatus, STATUS_INTERVAL_MS);
}

// =========================================================================
// Worker message handling
// =========================================================================

function handleWorkerMessage(workerId, msg) {
    switch (msg.type) {
        case 'ready':
            sendLog(`${formatTimestamp()} [Worker ${workerId}] Ready`);
            break;

        case 'events':
            forwardEvents(workerId, msg.events);
            break;

        case 'done':
            sendLog(`${formatTimestamp()} [Worker ${workerId}] Done (${msg.reason || 'limit reached'})`);
            workerDone(workerId);
            break;

        case 'error':
            sendLog(`${formatTimestamp()} [Worker ${workerId}] Error: ${msg.error}`, 'error');
            workerDone(workerId);
            break;
    }
}

function workerDone(workerId) {
    workersFinished++;
    if (workersFinished >= fuzzWorkers.length) {
        finalizeCampaign();
    }
}

// =========================================================================
// Event forwarding — dedup + classify (matches main fuzzer output)
// =========================================================================

function forwardEvents(workerId, events) {
    for (const event of events) {
        if (event.includes('falsified')) {
            const match = event.match(/Test (.+) falsified/);
            const testName = match ? match[1] : event;
            if (!reportedFalsified.has(testName)) {
                reportedFalsified.add(testName);
                sendLog(`${formatTimestamp()} [Worker ${workerId}] ${event}`, 'error');
            }
        } else if (event.includes('New coverage')) {
            sendLog(`${formatTimestamp()} [Worker ${workerId}] ${event}`, 'success');
        } else if (event.includes('New maximum value')) {
            sendLog(`${formatTimestamp()} [Worker ${workerId}] ${event}`, 'success');
        } else if (event.includes('Shrinking') || event.includes('shrunk to')) {
            sendLog(`${formatTimestamp()} [Worker ${workerId}] ${event}`, 'dim');
        } else {
            sendLog(`${formatTimestamp()} [Worker ${workerId}] ${event}`);
        }
    }
}

// =========================================================================
// Status reporting — reads SharedState via WasmSharedFuzzer.status()
// =========================================================================

function printStatus() {
    if (!running || !fuzzer) return;

    try {
        const statusJson = fuzzer.status();
        const status = JSON.parse(statusJson);
        if (status.error) return;

        status.running = running;
        status.workers_active = fuzzWorkers.length - workersFinished;
        status.workers_total = numWorkers;

        send('status', { data: status });
    } catch {}
}

// =========================================================================
// Campaign completion
// =========================================================================

function finalizeCampaign() {
    if (!running) return;

    if (statusInterval) {
        clearInterval(statusInterval);
        statusInterval = null;
    }

    printStatus();
    running = false;

    sendLog(`${formatTimestamp()} All workers stopped.`);

    // Terminate any remaining workers
    for (const w of fuzzWorkers) {
        try { w.terminate(); } catch {}
    }

    // Format final results with traces
    let finalResults = '';
    try {
        finalResults = fuzzer.get_final_results();
    } catch (err) {
        sendLog(`Warning: trace formatting failed: ${err.message}`, 'dim');
        finalResults = 'Error formatting results';
    }

    fuzzWorkers = [];

    send('fuzzing_done', { finalResults, wasStopped: stopRequested });
}

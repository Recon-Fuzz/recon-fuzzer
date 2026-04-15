// Fuzzer Web Worker — all WASM/EVM runs off the main thread
import init, { WasmFuzzer } from '../pkg/browser_fuzzer.js';

let fuzzer = null;
let running = false;
let stopRequested = false;

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

// =========================================================================
// Message handler
// =========================================================================

onmessage = async (e) => {
    const msg = e.data;

    switch (msg.type) {
        case 'init': {
            try {
                await init();
                send('init_done');
            } catch (err) {
                send('init_error', { error: err.message });
            }
            break;
        }

        case 'create_fuzzer': {
            try {
                fuzzer = new WasmFuzzer(msg.config);
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

        case 'deploy_raw': {
            if (!fuzzer) { send('result', { method: 'deploy_raw', data: { success: false, error: 'No fuzzer' } }); break; }
            try {
                sendLog(`Deploying ${msg.name}...`);
                const result = parseResult(fuzzer.deploy_raw(msg.name, msg.abi, msg.bytecode));
                send('result', { method: 'deploy_raw', data: result });
            } catch (err) {
                send('result', { method: 'deploy_raw', data: { success: false, error: err.message } });
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
            running = true;
            stopRequested = false;
            fuzzLoop();
            break;
        }

        case 'stop': {
            stopRequested = true;
            break;
        }

        case 'run_more': {
            if (!fuzzer || running) break;
            running = true;
            stopRequested = false;
            fuzzLoop();
            break;
        }
    }
};

// =========================================================================
// Fuzzing loop — runs entirely in worker thread
// =========================================================================

async function fuzzLoop() {
    send('fuzzing_started');

    while (running && !stopRequested) {
        // Run larger batches since we're off the main thread (500 steps per batch)
        const result = parseResult(fuzzer.run_steps(500));
        if (!result) continue;

        // Send status update to main thread
        send('status', { data: result });

        if (!result.running) {
            running = false;
            break;
        }

        // Yield briefly to allow stop messages to be processed
        await new Promise(r => setTimeout(r, 0));
    }

    if (stopRequested && fuzzer) {
        send('log', { msg: 'Stopping... shrinking...', cls: '' });
        fuzzer.stop();
        send('log', { msg: 'Done.', cls: 'success' });
    }

    running = false;

    // Send final results
    let finalResults = '';
    try {
        finalResults = fuzzer.get_final_results() || '';
    } catch (err) {
        // ignore
    }

    send('fuzzing_done', { finalResults, wasStopped: stopRequested });
}

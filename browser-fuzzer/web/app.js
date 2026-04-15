// Main thread — UI only. All WASM runs in coordinator + fuzzer workers.
//
// Matches main fuzzer's CLI output patterns:
// - Echidna-style status line: [status] tests: X/Y, fuzzing: N/M, cov: C, corpus: K
// - Per-worker messages: [Worker N] New coverage: X instr, Y seqs in corpus
// - Test result strip with colored indicators
// - Real-time terminal-style log output (right panel)

let configTestMode = null;
let wasmReady = false;
let wasmReadyPromise;
let wasmReadyResolve;

const output = document.getElementById('output');
const statusText = document.getElementById('statusText');
const artifactInfo = document.getElementById('artifactInfo');
const contractSelect = document.getElementById('contractSelect');
const testResults = document.getElementById('testResults');
const btnDeployFuzz = document.getElementById('btnDeployFuzz');
const btnStop = document.getElementById('btnStop');
const testModeSelect = document.getElementById('testModeSelect');
const workersInput = document.getElementById('workersInput');

const testLimitInput = document.getElementById('testLimitInput');
const seqLenInput = document.getElementById('seqLenInput');
const shrinkLimitInput = document.getElementById('shrinkLimitInput');
const seedInput = document.getElementById('seedInput');
const maxTimeDelayInput = document.getElementById('maxTimeDelayInput');
const maxBlockDelayInput = document.getElementById('maxBlockDelayInput');


function log(msg, cls) {
    const line = document.createElement('div');
    if (cls) line.className = cls;
    line.textContent = typeof msg === 'object' ? JSON.stringify(msg, null, 2) : msg;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}

function getConfigJson() {
    return JSON.stringify({
        seed: parseInt(seedInput.value) || 0,
        seq_len: parseInt(seqLenInput.value) || 100,
        test_limit: parseInt(testLimitInput.value) || 1000000,
        shrink_limit: parseInt(shrinkLimitInput.value) || 5000,
        max_value: "0xffffffffffffffffffffffffffffffff",
        max_time_delay: parseInt(maxTimeDelayInput.value) || 604800,
        max_block_delay: parseInt(maxBlockDelayInput.value) || 60480,
    });
}

// =========================================================================
// Coordinator setup — replaces single worker with coordinator + N workers
// =========================================================================

const coordinator = new Worker('coordinator.js', { type: 'module' });

// Terminate coordinator on page unload to prevent leaked workers
window.addEventListener('beforeunload', () => {
    coordinator.postMessage({ type: 'stop' });
    coordinator.terminate();
});

// Pending RPC calls: method -> resolve function
const pendingRPC = new Map();

function workerCall(type, data) {
    return new Promise((resolve) => {
        pendingRPC.set(type, resolve);
        coordinator.postMessage({ type, ...data });
    });
}

// Wait for WASM init
wasmReadyPromise = new Promise(r => { wasmReadyResolve = r; });

coordinator.addEventListener('message', (e) => {
    const msg = e.data;

    switch (msg.type) {
        case 'init_done':
            wasmReady = true;
            wasmReadyResolve();
            statusText.textContent = 'WASM ready';
            output.textContent = '';
            log('Ready. Upload build-info JSON and optionally echidna.yaml.');
            break;

        case 'init_error':
            statusText.textContent = 'WASM failed';
            log('WASM load error: ' + msg.error, 'error');
            break;

        case 'log':
            log(msg.msg, msg.cls);
            break;

        case 'result': {
            const resolve = pendingRPC.get(msg.method);
            if (resolve) {
                pendingRPC.delete(msg.method);
                resolve(msg.data);
            }
            break;
        }

        case 'status': {
            const result = msg.data;
            if (!result) break;

            // Process events — all go to log output like main fuzzer's terminal
            if (result.events && result.events.length > 0) {
                for (const event of result.events) {
                    if (event.includes('[status]')) {
                        // Log status line to output (terminal-style)
                        log(event, 'dim');
                        // Short version for top bar
                        const shortStatus = event.replace(/\[.*?\]\s*\[status\]\s*/, '');
                        statusText.textContent = shortStatus;
                    } else {
                        const isFailure = event.includes('falsified');
                        const isCoverage = event.includes('New coverage');
                        const isOpt = event.includes('New maximum value');
                        log(event, isFailure ? 'error' : (isCoverage || isOpt) ? 'success' : '');
                    }
                }
            }

            // Update test results strip — matches main fuzzer's test display
            updateTestStrip(result.tests);
            break;
        }

        case 'fuzzing_started':
            btnStop.disabled = false;
            btnDeployFuzz.disabled = true;
            break;

        case 'fuzzing_done':
            btnStop.disabled = true;
            btnDeployFuzz.disabled = false;
            log(msg.wasStopped ? 'Stopped.' : 'Fuzzing complete.', 'success');
            if (msg.finalResults) {
                // Print final results line by line with appropriate coloring
                // (matches main fuzzer's CLI output)
                log('');
                log('═══════════════════════════════════════════════════════════');
                log('  FINAL RESULTS');
                log('═══════════════════════════════════════════════════════════');
                for (const line of msg.finalResults.split('\n')) {
                    if (line.includes('failed!')) {
                        log(line, 'error');
                    } else if (line.includes('passing')) {
                        log(line, 'success');
                    } else if (line.includes('max value:')) {
                        log(line, 'success');
                    } else if (line.includes('Call sequence:')) {
                        log(line, '');
                    } else if (line.includes('Traces:')) {
                        log(line, 'dim');
                    } else if (line.trim().startsWith('Unique') || line.trim().startsWith('Calls') || line.trim().startsWith('Corpus') || line.trim().startsWith('Workers') || line.trim().startsWith('Total') || line.trim().startsWith('Coverage') || line.trim().startsWith('Elapsed')) {
                        log(line, 'dim');
                    } else {
                        log(line);
                    }
                }
                log('═══════════════════════════════════════════════════════════');
            }
            break;
    }
});

// Init WASM in coordinator
coordinator.postMessage({ type: 'init' });

// =========================================================================
// Test results strip — matches main fuzzer's test status display
// =========================================================================

function updateTestStrip(tests) {
    if (!tests || tests.length === 0) return;

    let html = '';
    for (const test of tests) {
        // Color scheme matches Echidna:
        // Red = FAILED/solved, Yellow = shrinking, Green = passed, Gray = open
        const state = test.state;
        const isFailed = state === 'FAILED';
        const isShrinking = typeof state === 'string' && state.startsWith('shrinking');
        const isPassed = state === 'passed';

        const color = isFailed ? '#f85149' :
                      isPassed ? '#3fb950' :
                      isShrinking ? '#d29922' : '#8b949e';
        const icon = isFailed ? '\u2717' :
                     isPassed ? '\u2713' :
                     isShrinking ? '\u21BB' : '\u2022';

        let label = `${icon} ${test.name}: ${state}`;
        if (test.value) label += ` (${test.value})`;
        if (test.reproducer_len > 0) label += ` [${test.reproducer_len} txs]`;
        html += `<span class="test-item" style="color:${color}">${label}</span>`;
    }
    testResults.innerHTML = html;
}

// =========================================================================
// Config loading
// =========================================================================

document.getElementById('configFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
        await wasmReadyPromise;
        const text = await file.text();
        await workerCall('create_fuzzer', { config: getConfigJson() });

        const result = await workerCall('load_config', { yaml: text });
        if (result && result.success) {
            // Apply all parsed settings to UI inputs (matches main fuzzer's EConfig)
            seqLenInput.value = result.seq_len;
            testLimitInput.value = result.test_limit;
            shrinkLimitInput.value = result.shrink_limit;
            if (result.seed && result.seed !== 0) {
                seedInput.value = result.seed;
            }
            if (result.max_time_delay) {
                maxTimeDelayInput.value = result.max_time_delay;
            }
            if (result.max_block_delay) {
                maxBlockDelayInput.value = result.max_block_delay;
            }
            if (result.workers) {
                workersInput.value = result.workers;
            }
            if (result.test_mode) {
                configTestMode = result.test_mode;
                testModeSelect.value = result.test_mode;
            }
            log(`Config loaded: testMode=${result.test_mode || 'auto'}, seqLen=${result.seq_len}, testLimit=${result.test_limit}, shrinkLimit=${result.shrink_limit}${result.workers ? ', workers=' + result.workers : ''}${result.seed ? ', seed=' + result.seed : ''}`, 'success');
        } else {
            log('Config failed: ' + (result ? result.error : 'unknown'), 'error');
        }
    } catch (err) {
        log('Config error: ' + err.message, 'error');
    }
});

// =========================================================================
// Artifact loading
// =========================================================================

document.getElementById('artifactFiles').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files);
    if (files.length === 0) return;

    await wasmReadyPromise;
    artifactInfo.textContent = `Reading ${files.length} file(s)...`;
    await workerCall('create_fuzzer', { config: getConfigJson() });

    let loadedArtifacts = [];

    for (const file of files) {
        try {
            const text = await file.text();
            log(`Reading ${file.name} (${(text.length / 1024 / 1024).toFixed(1)} MB)...`);
            const json = JSON.parse(text);

            if (json.output && json.output.contracts) {
                log('Detected build-info format...');
                for (const [filePath, fileContracts] of Object.entries(json.output.contracts)) {
                    for (const [contractName, contractData] of Object.entries(fileContracts)) {
                        const bc = contractData.evm?.bytecode?.object;
                        if (bc && bc !== '0x' && bc.length > 10) {
                            let metadata = contractData.metadata;
                            if (typeof metadata === 'string') {
                                try { metadata = JSON.parse(metadata); } catch { metadata = null; }
                            }
                            if (!metadata) {
                                metadata = { settings: { compilationTarget: { [filePath]: contractName } } };
                            } else if (!metadata.settings?.compilationTarget) {
                                if (!metadata.settings) metadata.settings = {};
                                metadata.settings.compilationTarget = { [filePath]: contractName };
                            }
                            loadedArtifacts.push(JSON.stringify({
                                abi: contractData.abi || [],
                                bytecode: { object: bc },
                                deployedBytecode: { object: contractData.evm?.deployedBytecode?.object || '' },
                                metadata,
                            }));
                        }
                    }
                }
                log(`Extracted ${loadedArtifacts.length} contracts.`);
            } else if (json.abi && json.bytecode?.object && json.bytecode.object !== '0x') {
                loadedArtifacts.push(text);
            }
        } catch (err) {
            log(`Error: ${file.name}: ${err.message}`, 'error');
        }
    }

    if (loadedArtifacts.length === 0) {
        log('No valid artifacts found.', 'error');
        return;
    }

    artifactInfo.textContent = `Loading ${loadedArtifacts.length} artifacts...`;
    const result = await workerCall('load_artifacts', { artifactsJson: JSON.stringify(loadedArtifacts) });

    if (!result || !result.success) {
        log('Failed: ' + (result ? result.error : 'unknown'), 'error');
        return;
    }

    contractSelect.innerHTML = '';
    // Find best contract to auto-select:
    // 1. WASM-detected test_contract (has echidna_ tests)
    // 2. Contract named "CryticTester" (Echidna convention)
    // 3. First contract (fallback)
    let autoSelect = result.test_contract || null;
    for (const name of result.contracts) {
        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        if (result.has_echidna_tests && result.test_contract === name) {
            opt.textContent += ' (echidna_)';
        }
        // Check for CryticTester if WASM didn't detect one
        if (!autoSelect && name === 'CryticTester') {
            autoSelect = name;
        }
        contractSelect.appendChild(opt);
    }
    if (autoSelect) {
        contractSelect.value = autoSelect;
        log(`Auto-selected: ${autoSelect}`, 'success');
    }

    artifactInfo.textContent = `${result.contracts.length} contracts loaded.`;
    log(`Found ${result.contracts.length} contracts.`, 'success');
    if (result.test_contract) log(`Test contract: ${result.test_contract}`, 'success');

    if (configTestMode) {
        testModeSelect.value = configTestMode;
    } else if (result.recommended_mode) {
        testModeSelect.value = result.recommended_mode;
        log(`Mode: ${result.recommended_mode}`, 'success');
    }

    btnDeployFuzz.disabled = false;
});

// =========================================================================
// Deploy & Fuzz — now with multi-worker support
// =========================================================================

btnDeployFuzz.addEventListener('click', async () => {
    const contractName = contractSelect.value;
    if (!contractName) { log('Select a contract.', 'error'); return; }

    btnDeployFuzz.disabled = true;

    // Recreate fuzzer with current UI config (fresh state for each campaign)
    // Coordinator auto-reloads saved artifacts on create_fuzzer
    await workerCall('create_fuzzer', { config: getConfigJson() });

    const deployResult = await workerCall('deploy', { contractName });
    if (!deployResult || !deployResult.success) {
        log('Deploy failed: ' + (deployResult ? deployResult.error : 'unknown'), 'error');
        btnDeployFuzz.disabled = false;
        return;
    }
    log(`Deployed at ${deployResult.address}`, 'success');

    const mode = testModeSelect.value;
    const modeResult = await workerCall('set_mode', { mode });
    if (modeResult && modeResult.success) {
        log(`Mode: ${mode}, ${modeResult.tests_created} tests`, 'success');
        if (modeResult.tests_created === 0) {
            log(`Warning: 0 tests! Check mode for this contract.`, 'error');
        }
    } else {
        log('set_mode failed: ' + (modeResult ? modeResult.error : 'unknown'), 'error');
    }

    const numWorkers = parseInt(workersInput.value) || 4;
    log(`Starting campaign with ${numWorkers} workers...`, 'success');

    coordinator.postMessage({ type: 'start_fuzzing', numWorkers });
});

btnStop.addEventListener('click', () => {
    coordinator.postMessage({ type: 'stop' });
    btnStop.disabled = true;
    log('Stopping... (shrinking in progress)', '');
});

// =========================================================================
// Manual Deploy
// =========================================================================

document.getElementById('btnManualDeploy').addEventListener('click', async () => {
    const name = document.getElementById('manualName').value.trim();
    const abiJson = document.getElementById('manualAbi').value.trim();
    const bytecodeHex = document.getElementById('manualBytecode').value.trim();

    if (!name || !abiJson || !bytecodeHex) {
        log('Fill in all fields.', 'error');
        return;
    }

    await wasmReadyPromise;
    await workerCall('create_fuzzer', { config: getConfigJson() });

    const deployResult = await workerCall('deploy_raw', { name, abi: abiJson, bytecode: bytecodeHex });
    if (!deployResult || !deployResult.success) {
        log('Deploy failed: ' + (deployResult ? deployResult.error : 'unknown'), 'error');
        return;
    }
    log(`Deployed at ${deployResult.address}`, 'success');

    const mode = testModeSelect.value;
    const modeResult = await workerCall('set_mode', { mode });
    if (modeResult && modeResult.success) {
        log(`Mode: ${mode}, ${modeResult.tests_created} tests`, 'success');
    }

    const numWorkers = parseInt(workersInput.value) || 4;
    coordinator.postMessage({ type: 'start_fuzzing', numWorkers });
});

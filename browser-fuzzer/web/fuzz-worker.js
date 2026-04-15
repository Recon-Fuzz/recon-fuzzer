// Fuzz Worker — runs in its own Web Worker thread for true multi-core parallelism
//
// Receives { module, memory, state, workerId, seed } from coordinator.
// Calls initSync({ module, memory }) to join the shared WASM heap.
// Creates WasmFuzzWorker which gets Arc<SharedState> from the global OnceLock.
// Runs batch loop, sends events back to coordinator via postMessage.
//
// The RwLock in SharedState uses Atomics.wait/notify for cross-worker sync —
// identical to the main fuzzer's parking_lot::RwLock pattern.

const BATCH_SIZE = 100;  // Iterations per batch before yielding to event loop

self.onmessage = async (e) => {
    const { module, memory, state, workerId, seed } = e.data;

    try {
        // Import fresh copy of the WASM bindings (cache-busted for separate module state).
        // Each worker needs its own JS module scope with its own `wasm` variable,
        // but they all share the same underlying WebAssembly.Memory (SharedArrayBuffer).
        const shimUrl = '../pkg/browser_fuzzer.js?worker=' + workerId + '&t=' + Date.now();
        const shim = await import(shimUrl);

        // Join the shared WASM heap — same memory as coordinator + all other workers.
        // initSync({ module, memory }) creates a new WebAssembly.Instance that uses
        // the provided shared memory (imported memory) instead of creating a new one.
        shim.initSync({ module, memory });

        self.postMessage({ type: 'ready' });

        // Create WasmFuzzWorker — gets Arc<SharedState> from the global OnceLock
        // (same shared WASM heap → same OnceLock → same Arc<SharedState>).
        const worker = new shim.WasmFuzzWorker(state, workerId, seed);

        // Batch loop — run BATCH_SIZE iterations, drain events, yield to event loop.
        // This mirrors the main fuzzer's worker loop exactly.
        while (worker.is_running()) {
            worker.run_batch(BATCH_SIZE);

            // Drain events and send to coordinator
            const eventsJson = worker.drain_events();
            const events = JSON.parse(eventsJson);
            if (events.length > 0) {
                self.postMessage({ type: 'events', workerId, events });
            }

            // Yield to event loop — allows postMessage delivery and prevents starving
            // the coordinator's status polling. setTimeout(0) is sufficient since
            // real work happens in WASM (not JS event loop).
            await new Promise(resolve => setTimeout(resolve, 0));
        }

        const totalCalls = worker.call_count();
        worker.free();

        self.postMessage({
            type: 'done',
            workerId,
            reason: `completed ${totalCalls} calls`,
        });
    } catch (err) {
        self.postMessage({
            type: 'error',
            workerId,
            error: err.message || String(err),
        });
    }
};

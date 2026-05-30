// Runs the Rust → WASM crypto off the main thread, so encryption/decryption never freezes the
// UI. The main thread (app.js) posts { id, op, data, passphrase }; we reply with the result or
// a generic error. The WASM module is initialized once, here in the worker.
import init, { encrypt, decrypt } from './pkg/pqfe_wasm.js';

const ready = init()
    .then(() => self.postMessage({ type: 'ready' }))
    .catch((e) => self.postMessage({ type: 'error', error: String(e?.message ?? e) }));

self.onmessage = async (event) => {
    const { id, op, data, passphrase } = event.data ?? {};
    if (id === undefined) return;
    try {
        await ready;
        const result = op === 'encrypt' ? encrypt(data, passphrase) : decrypt(data, passphrase);
        // Transfer the result buffer back to avoid a copy.
        self.postMessage({ id, ok: true, result }, [result.buffer]);
    } catch (err) {
        self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
    }
};

// Wires up the encrypt/decrypt UI. All cryptography runs locally in the browser — preferably
// in a Web Worker (so the UI never freezes), with a graceful fallback to the main thread if
// module workers are unavailable. No file or passphrase is ever sent anywhere.

const MIN_PASSPHRASE = 8;
const EXTENSION = '.pqfe';
// The whole file is read into memory in the browser, so cap it to avoid OOMing the tab.
const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MiB

const $ = (id) => document.getElementById(id);

const els = {
    loading: $('loading'),
    app: $('app'),
    encFile: $('encFile'), encFileInfo: $('encFileInfo'), encPass: $('encPass'),
    encHint: $('encHint'), encBtn: $('encBtn'), encStatus: $('encStatus'),
    decFile: $('decFile'), decFileInfo: $('decFileInfo'), decPass: $('decPass'),
    decBtn: $('decBtn'), decStatus: $('decStatus'),
};

// ----------------------------------------------------------------- crypto backend

// Prefer a module Web Worker; fall back to running the WASM on the main thread.
function createWorkerBackend() {
    return new Promise((resolve, reject) => {
        let worker;
        try {
            worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
        } catch (e) {
            reject(e);
            return;
        }
        const pending = new Map();
        let nextId = 1;
        const timer = setTimeout(() => reject(new Error('worker init timed out')), 10000);

        const backend = {
            kind: 'worker',
            run(op, data, passphrase) {
                return new Promise((res, rej) => {
                    const id = nextId++;
                    pending.set(id, { res, rej });
                    worker.postMessage({ id, op, data, passphrase }, [data.buffer]);
                });
            },
        };

        worker.onmessage = (e) => {
            const m = e.data;
            if (m.type === 'ready') { clearTimeout(timer); resolve(backend); return; }
            if (m.type === 'error') { clearTimeout(timer); reject(new Error(m.error)); return; }
            const p = pending.get(m.id);
            if (!p) return;
            pending.delete(m.id);
            m.ok ? p.res(m.result) : p.rej(new Error(m.error));
        };
        worker.onerror = (e) => { clearTimeout(timer); reject(new Error(e.message || 'worker error')); };
    });
}

async function createMainThreadBackend() {
    const mod = await import('./pkg/pqfe_wasm.js');
    await mod.default();
    return {
        kind: 'main',
        async run(op, data, passphrase) {
            return op === 'encrypt' ? mod.encrypt(data, passphrase) : mod.decrypt(data, passphrase);
        },
    };
}

let backend = null;

// ----------------------------------------------------------------- helpers

function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes, unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return `${value.toFixed(value < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

function showStatus(el, message, kind) {
    el.hidden = false;
    el.textContent = message;
    el.className = `status ${kind}`;
}

function download(fileName, bytes) {
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

const readFile = (file) =>
    new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(file);
    });

function tooLarge(file, statusEl) {
    if (file.size > MAX_FILE_BYTES) {
        showStatus(statusEl, `File is too large for this in-browser demo (limit ${formatBytes(MAX_FILE_BYTES)}).`, 'error');
        return true;
    }
    return false;
}

function refreshEncryptButton() {
    const file = els.encFile.files[0];
    const pass = els.encPass.value;
    els.encHint.hidden = !(pass.length > 0 && pass.length < MIN_PASSPHRASE);
    els.encBtn.disabled = !(backend && file && pass.length >= MIN_PASSPHRASE);
}

function refreshDecryptButton() {
    els.decBtn.disabled = !(backend && els.decFile.files[0] && els.decPass.value.length > 0);
}

function wireFileInfo(input, info, refresh) {
    input.addEventListener('change', () => {
        const file = input.files[0];
        if (file) {
            info.hidden = false;
            info.textContent = `${file.name} (${formatBytes(file.size)})`;
        } else {
            info.hidden = true;
        }
        refresh();
    });
}

// ----------------------------------------------------------------- actions

async function onEncrypt() {
    const file = els.encFile.files[0];
    if (!file || tooLarge(file, els.encStatus)) return;
    els.encBtn.disabled = true;
    showStatus(els.encStatus, 'Encrypting…', 'working');
    try {
        const data = await readFile(file);
        const container = await backend.run('encrypt', data, els.encPass.value);
        download(file.name + EXTENSION, container);
        showStatus(els.encStatus, `Encrypted ${file.name} → ${file.name + EXTENSION}.`, 'success');
        els.encPass.value = ''; // don't leave the passphrase sitting in the field
    } catch (e) {
        showStatus(els.encStatus, `Could not encrypt: ${e?.message ?? e}`, 'error');
    } finally {
        refreshEncryptButton();
    }
}

async function onDecrypt() {
    const file = els.decFile.files[0];
    if (!file || tooLarge(file, els.decStatus)) return;
    els.decBtn.disabled = true;
    showStatus(els.decStatus, 'Decrypting…', 'working');
    try {
        const data = await readFile(file);
        const plaintext = await backend.run('decrypt', data, els.decPass.value);
        const outName = file.name.toLowerCase().endsWith(EXTENSION)
            ? file.name.slice(0, -EXTENSION.length)
            : file.name + '.decrypted';
        download(outName, plaintext);
        showStatus(els.decStatus, `Decrypted ${file.name} → ${outName}.`, 'success');
        els.decPass.value = ''; // don't leave the passphrase sitting in the field
    } catch (e) {
        // The core returns a generic, no-oracle message for any authentication failure.
        showStatus(els.decStatus, e?.message ?? 'Could not decrypt the file.', 'error');
    } finally {
        refreshDecryptButton();
    }
}

// ----------------------------------------------------------------- startup

async function main() {
    try {
        backend = await createWorkerBackend();
    } catch {
        try {
            backend = await createMainThreadBackend();
        } catch (e) {
            showStatus(els.loading, `Failed to load the cryptography module: ${e?.message ?? e}`, 'error');
            return;
        }
    }

    els.loading.hidden = true;
    els.app.hidden = false;

    wireFileInfo(els.encFile, els.encFileInfo, refreshEncryptButton);
    wireFileInfo(els.decFile, els.decFileInfo, refreshDecryptButton);
    els.encPass.addEventListener('input', refreshEncryptButton);
    els.decPass.addEventListener('input', refreshDecryptButton);
    els.encBtn.addEventListener('click', onEncrypt);
    els.decBtn.addEventListener('click', onDecrypt);
}

main();

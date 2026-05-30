// Loads the Rust→WASM core and wires up the encrypt/decrypt UI. All cryptography runs locally
// in the browser; no file or passphrase is ever sent anywhere.
import init, { encrypt, decrypt } from './pkg/pqfe_wasm.js';

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

// Let the browser paint the "Working…" state before a synchronous WASM call blocks the thread.
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

function refreshEncryptButton() {
    const file = els.encFile.files[0];
    const pass = els.encPass.value;
    els.encHint.hidden = !(pass.length > 0 && pass.length < MIN_PASSPHRASE);
    els.encBtn.disabled = !(file && pass.length >= MIN_PASSPHRASE);
}

function refreshDecryptButton() {
    els.decBtn.disabled = !(els.decFile.files[0] && els.decPass.value.length > 0);
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

function tooLarge(file, statusEl) {
    if (file.size > MAX_FILE_BYTES) {
        showStatus(statusEl, `File is too large for this in-browser demo (limit ${formatBytes(MAX_FILE_BYTES)}).`, 'error');
        return true;
    }
    return false;
}

async function onEncrypt() {
    const file = els.encFile.files[0];
    if (!file || tooLarge(file, els.encStatus)) return;
    els.encBtn.disabled = true;
    showStatus(els.encStatus, 'Encrypting…', 'working');
    await nextFrame();
    try {
        const data = await readFile(file);
        const container = encrypt(data, els.encPass.value);
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
    await nextFrame();
    try {
        const data = await readFile(file);
        const plaintext = decrypt(data, els.decPass.value);
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

async function main() {
    try {
        await init();
    } catch (e) {
        showStatus(els.loading, `Failed to load the cryptography module: ${e?.message ?? e}`, 'error');
        return;
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

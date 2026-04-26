/**
 * fileHandler.js — File I/O utilities
 *
 * Provides:
 *   - readFileAsArrayBuffer(file) — read a File object into a Uint8Array
 *   - downloadFile(data, originalName, prefix) — trigger a browser download
 */


/**
 * Read a File object and return its contents as a Uint8Array.
 *
 * @param {File} file — the File selected by the user
 * @returns {Promise<Uint8Array>} — resolves with the file bytes
 */
export function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (e) => {
            resolve(new Uint8Array(e.target.result));
        };

        reader.onerror = () => {
            reject(new Error('Ошибка чтения файла'));
        };

        reader.readAsArrayBuffer(file);
    });
}


/**
 * Trigger a browser download of arbitrary binary data.
 *
 * Naming convention:
 *   originalName = "photo.png"
 *   prefix       = "encrypted"   → "encrypted_photo.png"
 *   prefix       = "decrypted"   → "decrypted_photo.png"
 *
 * @param {Uint8Array|Blob|string} data — payload to download
 * @param {string} originalName — original file name (used to build output name)
 * @param {string} prefix — prefix to prepend ("encrypted" / "decrypted")
 */
export function downloadFile(data, originalName, prefix) {
    const fileName = prefix ? `${prefix}_${originalName}` : originalName;

    let blob;
    if (data instanceof Blob) {
        blob = data;
    } else if (typeof data === 'string') {
        blob = new Blob([data], { type: 'text/plain' });
    } else {
        blob = new Blob([data], { type: 'application/octet-stream' });
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.style.display = 'none';

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
}

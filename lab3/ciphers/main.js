/**
 * main.js — Controller / DOM orchestration
 *
 * Imports modules:
 *   math.js        → isPrime (used transitively via rabin.js)
 *   rabin.js       → validateParams, rabinEncrypt, rabinDecrypt,
 *                    cipherToDecimalString, decimalStringToCipher
 *   fileHandler.js → readFileAsArrayBuffer, downloadFile
 *
 * Wires up every DOM element from index.html and manages application state.
 */

import {
    validateParams,
    rabinEncrypt,
    rabinDecrypt,
    cipherToDecimalString,
    decimalStringToCipher,
} from './rabin.js';

import {
    readFileAsArrayBuffer,
    downloadFile,
} from './fileHandler.js';


/* ================================================================== */
/*  Application state                                                  */
/* ================================================================== */
let currentFileData = null;   // Uint8Array — raw bytes of the selected file
let currentFileName = '';     // original file name
let lastCipherData = null;   // Uint8Array — last encryption result (raw cipher bytes)
let lastPlainData = null;   // Uint8Array — last decryption result (recovered bytes)
let operationMode = null;   // 'encrypt' | 'decrypt' | null

/* ================================================================== */
/*  DOM element cache (populated in init())                            */
/* ================================================================== */
let els = {};


/* ================================================================== */
/*  UI helpers                                                         */
/* ================================================================== */

/** Show an error message in .error-messages */
function showError(msg) {
    const box = els.errorMessages;
    if (!box) return;
    box.querySelector('div').textContent = msg;
    box.classList.add('active');
}

/** Clear the error banner */
function clearError() {
    const box = els.errorMessages;
    if (!box) return;
    box.querySelector('div').textContent = '';
    box.classList.remove('active');
}

/** Display text in the output section */
function showOutput(text) {
    if (els.resultOutput) els.resultOutput.textContent = text;
    if (els.outputSection) els.outputSection.style.display = 'block';
}

/** Hide the output section */
function hideOutput() {
    if (els.resultOutput) els.resultOutput.textContent = '';
    if (els.outputSection) els.outputSection.style.display = 'none';
}


/* ================================================================== */
/*  Input parsing / validation                                         */
/* ================================================================== */

/**
 * Read p, q, b from the DOM, validate, and return parsed BigInts.
 * Shows an error and returns null on failure.
 *
 * @returns {{ p: bigint, q: bigint, b: bigint, n: bigint } | null}
 */
function getParams() {
    clearError();

    const pStr = els.pInput?.value?.trim() || '';
    const qStr = els.qInput?.value?.trim() || '';
    const bStr = els.bInput?.value?.trim() || '';

    if (!pStr) { showError('Параметр p обязателен'); return null; }
    if (!qStr) { showError('Параметр q обязателен'); return null; }
    if (!bStr) { showError('Параметр b обязателен'); return null; }

    let p, q, b;
    try {
        p = BigInt(pStr);
        q = BigInt(qStr);
        b = BigInt(bStr);
    } catch {
        showError('Некорректные числовые параметры');
        return null;
    }

    const result = validateParams(p, q, b);
    if (!result.valid) {
        showError(result.error);
        return null;
    }

    return { p, q, b, n: result.n };
}


/* ================================================================== */
/*  File handling                                                      */
/* ================================================================== */

async function handleFileSelect() {
    const file = els.fileInput?.files?.[0];
    if (!file) return;

    currentFileName = file.name;
    if (els.fileName) els.fileName.textContent = file.name;

    try {
        currentFileData = await readFileAsArrayBuffer(file);
        clearError();
    } catch (err) {
        showError(err.message);
    }
}


/* ================================================================== */
/*  Encrypt                                                            */
/* ================================================================== */

function encryptFile() {
    clearError();

    const params = getParams();
    if (!params) return;

    if (!currentFileData || currentFileData.length === 0) {
        showError('Выберите файл');
        return;
    }

    const { b, n } = params;

    try {
        const cipherBytes = rabinEncrypt(currentFileData, b, n);

        // Save for later download
        lastCipherData = cipherBytes;
        lastPlainData = null;
        operationMode = 'encrypt';

        // Display cipher blocks as decimal numbers
        const decStr = cipherToDecimalString(cipherBytes, n);
        showOutput(decStr);
    } catch (err) {
        showError('Ошибка шифрования: ' + err.message);
    }
}


/* ================================================================== */
/*  Decrypt                                                            */
/* ================================================================== */

function decryptFile() {
    clearError();

    const params = getParams();
    if (!params) return;

    const { p, q, b, n } = params;

    // Get cipher text — either from the last encryption or from the output box
    let cipherBytes;

    if (lastCipherData) {
        // Decrypt the result of a previous encryption
        cipherBytes = lastCipherData;
    } else {
        // Try to parse decimal text from the output area
        const text = els.resultOutput?.textContent?.trim();
        if (!text) {
            showError('Сначала зашифруйте файл или загрузите шифротекст');
            return;
        }
        try {
            cipherBytes = decimalStringToCipher(text, n);
        } catch {
            showError('Не удалось разобрать шифротекст');
            return;
        }
    }

    try {
        const plainBytes = rabinDecrypt(cipherBytes, b, n, p, q);

        lastPlainData = plainBytes;
        lastCipherData = null;
        operationMode = 'decrypt';

        // Show preview (first 200 bytes as decimals)
        const preview = Array.from(plainBytes).slice(0, 200).join(' ');
        showOutput(preview + (plainBytes.length > 200 ? ' …' : ''));
    } catch (err) {
        showError('Ошибка дешифрования: ' + err.message);
    }
}


/* ================================================================== */
/*  Save / Download                                                    */
/* ================================================================== */

function saveData() {
    if (operationMode === 'encrypt' && lastCipherData) {
        // Save encrypted data as binary file
        // file.png → encrypted_file.png
        downloadFile(lastCipherData, currentFileName || 'data.bin', 'encrypted');
    } else if (operationMode === 'decrypt' && lastPlainData) {
        // Save decrypted data
        // encrypted_file.png → decrypted_encrypted_file.png
        downloadFile(lastPlainData, currentFileName || 'data.bin', 'decrypted');
    } else {
        showError('Нет данных для сохранения');
    }
}


/* ================================================================== */
/*  Clear                                                              */
/* ================================================================== */

function clearAll() {
    if (els.pInput) els.pInput.value = '';
    if (els.qInput) els.qInput.value = '';
    if (els.bInput) els.bInput.value = '';
    if (els.fileName) els.fileName.textContent = 'файл не выбран';
    if (els.fileInput) els.fileInput.value = '';

    currentFileData = null;
    currentFileName = '';
    lastCipherData = null;
    lastPlainData = null;
    operationMode = null;

    hideOutput();
    clearError();
}


/* ================================================================== */
/*  Initialisation                                                     */
/* ================================================================== */

function init() {
    els = {
        pInput: document.getElementById('p_input'),
        qInput: document.getElementById('q_input'),
        bInput: document.getElementById('b_input'),
        fileInput: document.getElementById('file_input'),
        btnChooseFile: document.getElementById('btn_choose_file'),
        fileName: document.getElementById('file_name'),
        resultOutput: document.getElementById('result_output'),
        outputSection: document.getElementById('output_section'),
        btnSave: document.getElementById('btn_save'),
        errorMessages: document.querySelector('.error-messages'),
    };

    // File picker: visible button triggers hidden <input type="file">
    els.btnChooseFile?.addEventListener('click', () => els.fileInput?.click());
    els.fileInput?.addEventListener('change', handleFileSelect);

    // Action buttons (selected by class — matches the HTML)
    document.querySelector('.action-btn-encrypt')?.addEventListener('click', encryptFile);
    document.querySelector('.action-btn-decrypt')?.addEventListener('click', decryptFile);
    document.querySelector('.action-btn-clear')?.addEventListener('click', clearAll);
    els.btnSave?.addEventListener('click', saveData);

    // Clear errors on typing
    els.pInput?.addEventListener('input', clearError);
    els.qInput?.addEventListener('input', clearError);
    els.bInput?.addEventListener('input', clearError);
}


// Auto-run when the DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
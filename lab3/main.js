import { validateParams, encryptBytes, decryptValues } from './ciphers/rabin.js';

// ===== Элементы DOM =====
const pInput = document.getElementById('p_input');
const qInput = document.getElementById('q_input');
const bInput = document.getElementById('b_input');
const fileInput = document.getElementById('file_input');
const btnChooseFile = document.getElementById('btn_choose_file');
const fileNameLabel = document.getElementById('file_name');
const errorMessages = document.querySelector('.error-messages');

const btnEncrypt = document.querySelector('.action-btn-encrypt');
const btnDecrypt = document.querySelector('.action-btn-decrypt');
const btnClear = document.querySelector('.action-btn-clear');
const btnSave = document.getElementById('btn_save');

const outputSection = document.getElementById('output_section');
const resultOutput = document.getElementById('result_output');


// Состояние приложения
let loadedFileBytes = null;       // Uint8Array загруженного файла
let loadedFileName = '';          // Исходное имя файла
let lastResultData = null;        // Uint8Array или массив BigInt (зависит от режима)
let currentMode = '';             // 'encrypt' или 'decrypt'


// Вспомогательные функции

/**
 * Отображает сообщение об ошибке пользователю.
 * @param {string} message - Сообщение об ошибке для отображения.
 */
function showError(message) {
    errorMessages.textContent = message;
    errorMessages.classList.add('active');
}

/**
 * Скрывает отображение сообщения об ошибке.
 */
function hideError() {
    errorMessages.textContent = '';
    errorMessages.classList.remove('active');
}

/**
 * Парсит строку в BigInt, гарантируя что она содержит только цифры.
 * @param {string} value - Строковое значение для парсинга.
 * @param {string} paramName - Имя параметра (для сообщений об ошибках).
 * @returns {bigint} Спарсенное значение BigInt.
 * @throws {Error} Если значение не является неотрицательным целым.
 */
function parseBigIntStrict(value, paramName) {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new Error(`${paramName} должно быть неотрицательным целым числом.`);
    }
    return BigInt(trimmed);
}


// Обработчики событий

// Обработка выбора файла через кнопку "Выбрать файл"
btnChooseFile.addEventListener('click', () => {
    fileInput.click();
});

// Обработка изменения ввода файла - читаем файл как байты
fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
        loadedFileBytes = new Uint8Array(reader.result);
        loadedFileName = file.name;
        fileNameLabel.textContent = file.name;
        hideError();
    };
    reader.readAsArrayBuffer(file);
    fileInput.value = '';
});

// Обработка нажатия кнопки шифрования
btnEncrypt.addEventListener('click', () => {
    hideError();
    try {
        const p = parseBigIntStrict(pInput.value, "p");
        const q = parseBigIntStrict(qInput.value, "q");
        const b = parseBigIntStrict(bInput.value, "b");
        const n = validateParams(p, q, b);

        if (!loadedFileBytes) {
            showError("Выберите файл для шифрования.");
            return;
        }

        const encrypted = encryptBytes(loadedFileBytes, n, b);
        lastResultData = encrypted;
        currentMode = 'encrypt';

        // Отображаем зашифрованные значения как десятичные числа через пробел
        resultOutput.textContent = encrypted.map(v => v.toString()).join(" ");
        outputSection.style.display = 'block';
    } catch (e) {
        showError(e.message);
    }
});

// Обработка нажатия кнопки расшифрования
btnDecrypt.addEventListener('click', () => {
    hideError();
    try {
        const p = parseBigIntStrict(pInput.value, "p");
        const q = parseBigIntStrict(qInput.value, "q");
        const b = parseBigIntStrict(bInput.value, "b");
        validateParams(p, q, b);

        if (!loadedFileBytes) {
            showError("Выберите файл для расшифрования.");
            return;
        }

        // Зашифрованный файл содержит десятичные числа через пробел
        const decoder = new TextDecoder();
        const text = decoder.decode(loadedFileBytes).trim();
        const values = text.split(/\s+/).map(x => parseBigIntStrict(x, "элемент шифротекста"));

        const decrypted = decryptValues(values, p, q, b);
        lastResultData = decrypted;
        currentMode = 'decrypt';

        // Пытаемся отобразить как текст, иначе показываем заглушку
        try {
            resultOutput.textContent = new TextDecoder().decode(decrypted);
        } catch (e) {
            resultOutput.textContent = "[Бинарные данные]";
        }
        outputSection.style.display = 'block';
    } catch (e) {
        showError(e.message);
    }
});

// Обработка нажатия кнопки очистки - сброс всех вводов и состояния
btnClear.addEventListener('click', () => {
    hideError();
    pInput.value = '';
    qInput.value = '';
    bInput.value = '';
    loadedFileBytes = null;
    loadedFileName = '';
    fileNameLabel.textContent = 'файл не выбран';
    lastResultData = null;
    resultOutput.textContent = '';
    outputSection.style.display = 'none';
});

// Обработка нажатия кнопки сохранения - скачиваем результат как файл
btnSave.addEventListener('click', () => {
    if (!lastResultData) {
        showError("Нет результата для сохранения.");
        return;
    }

    let blob;
    let fileName = "result_" + loadedFileName;

    if (currentMode === 'encrypt') {
        // Зашифрованный вывод - массив BigInt сохраняем как текст через пробел
        const text = lastResultData.map(v => v.toString()).join(" ");
        blob = new Blob([text], { type: 'text/plain' });
        if (!fileName.endsWith(".txt")) fileName += ".txt";
    } else {
        // Расшифрованный вывод - бинарные данные
        blob = new Blob([lastResultData], { type: 'application/octet-stream' });
    }

    // Запускаем скачивание файла
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
});
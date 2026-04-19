import { validateParams, encryptBytes, decryptValues } from './ciphers/rabin.js';

// ===== DOM-элементы =====
const p_input = document.getElementById('p_input');
const q_input = document.getElementById('q_input');
const b_input = document.getElementById('b_input');
const file_input = document.getElementById('file_input');
const btn_choose_file = document.getElementById('btn_choose_file');
const file_name_label = document.getElementById('file_name');
const error_messages = document.querySelector('.error-messages');

const btn_encrypt = document.querySelector('.action-btn-encrypt');
const btn_decrypt = document.querySelector('.action-btn-decrypt');
const btn_clear = document.querySelector('.action-btn-clear');
const btn_save = document.getElementById('btn_save');

const output_section = document.getElementById('output_section');
const result_output = document.getElementById('result_output');

// ===== Состояние =====
let loaded_file_bytes = null;
let loaded_file_name = '';
let last_result_data = null; // Может быть Uint8Array или массив BigInt
let current_mode = ''; // 'encrypt' или 'decrypt'

// ===== Утилиты =====
function show_error(message) {
    error_messages.textContent = message;
    error_messages.classList.add('active');
}

function hide_error() {
    error_messages.textContent = '';
    error_messages.classList.remove('active');
}

function parseBigIntStrict(value, name) {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new Error(`${name} должно быть целым неотрицательным числом.`);
    }
    return BigInt(trimmed);
}

// ===== Обработчики событий =====
btn_choose_file.addEventListener('click', () => {
    file_input.click();
});

file_input.addEventListener('change', () => {
    const file = file_input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
        loaded_file_bytes = new Uint8Array(reader.result);
        loaded_file_name = file.name;
        file_name_label.textContent = file.name;
        hide_error();
    };
    reader.readAsArrayBuffer(file);
    file_input.value = '';
});

btn_encrypt.addEventListener('click', () => {
    hide_error();
    try {
        const p = parseBigIntStrict(p_input.value, "p");
        const q = parseBigIntStrict(q_input.value, "q");
        const b = parseBigIntStrict(b_input.value, "b");
        const n = validateParams(p, q, b);

        if (!loaded_file_bytes) {
            show_error("Выберите файл для шифрования");
            return;
        }

        const encrypted = encryptBytes(loaded_file_bytes, n, b);
        last_result_data = encrypted;
        current_mode = 'encrypt';

        result_output.textContent = encrypted.map(v => v.toString()).join(" ");
        output_section.style.display = 'block';
    } catch (e) {
        show_error(e.message);
    }
});

btn_decrypt.addEventListener('click', () => {
    hide_error();
    try {
        const p = parseBigIntStrict(p_input.value, "p");
        const q = parseBigIntStrict(q_input.value, "q");
        const b = parseBigIntStrict(b_input.value, "b");
        validateParams(p, q, b);

        if (!loaded_file_bytes) {
            show_error("Выберите файл для дешифрования");
            return;
        }

        // Если файл зашифрован, он содержит десятичные числа через пробел
        const decoder = new TextDecoder();
        const text = decoder.decode(loaded_file_bytes).trim();
        const values = text.split(/\s+/).map(x => parseBigIntStrict(x, "элемент шифротекста"));

        const decrypted = decryptValues(values, p, q, b);
        last_result_data = decrypted;
        current_mode = 'decrypt';

        // Пытаемся отобразить как текст, если возможно
        try {
            result_output.textContent = new TextDecoder().decode(decrypted);
        } catch (e) {
            result_output.textContent = "[Бинарные данные]";
        }
        output_section.style.display = 'block';
    } catch (e) {
        show_error(e.message);
    }
});

btn_clear.addEventListener('click', () => {
    hide_error();
    p_input.value = '';
    q_input.value = '';
    b_input.value = '';
    loaded_file_bytes = null;
    loaded_file_name = '';
    file_name_label.textContent = 'файл не выбран';
    last_result_data = null;
    result_output.textContent = '';
    output_section.style.display = 'none';
});

btn_save.addEventListener('click', () => {
    if (!last_result_data) {
        show_error("Нет результата для сохранения");
        return;
    }

    let blob;
    let fileName = "result_" + loaded_file_name;

    if (current_mode === 'encrypt') {
        const text = last_result_data.map(v => v.toString()).join(" ");
        blob = new Blob([text], { type: 'text/plain' });
        if (!fileName.endsWith(".txt")) fileName += ".txt";
    } else {
        blob = new Blob([last_result_data], { type: 'application/octet-stream' });
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
});

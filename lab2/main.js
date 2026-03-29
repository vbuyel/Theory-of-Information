import { lfsr_process } from './ciphers/lfsr.js';

// ===== DOM-элементы =====
const register_input = document.getElementById('register_input');
const file_input = document.getElementById('file_input');
const btn_choose_file = document.getElementById('btn_choose_file');
const file_name_label = document.getElementById('file_name');
const error_messages = document.querySelector('.error-messages');

const btn_encrypt = document.querySelector('.action-btn-encrypt');
const btn_decrypt = document.querySelector('.action-btn-decrypt');
const btn_clear = document.querySelector('.action-btn-clear');
const btn_save = document.getElementById('btn_save');

const output_section = document.getElementById('output_section');
const key_output = document.getElementById('key_output');
const source_output = document.getElementById('source_output');
const result_output = document.getElementById('result_output');

// ===== Хранение загруженного файла в памяти =====
let loaded_file_bytes = null;
let loaded_file_name = '';
let last_result_bytes = null;
let is_decrypted = false;
let prev_extantion = '';


// ===== Утилиты =====

/**
 * Показать ошибку.
 */
function show_error(message) {
    error_messages.textContent = message;
    error_messages.classList.add('active');
}

/**
 * Скрыть ошибку.
 */
function hide_error() {
    error_messages.textContent = '';
    error_messages.classList.remove('active');
}

/**
 * Форматирует массив бит для вывода — группами по 8, через пробел.
 */
function format_bits(bits) {
    let result = '';
    for (let i = 0; i < bits.length; i++) {
        result += bits[i];
        if ((i + 1) % 8 === 0 && i + 1 < bits.length) {
            result += ' ';
        }
    }
    return result;
}

/**
 * Парсит значение поля регистра — возвращает массив из 25 чисел (0/1)
 * или null, если ввод невалиден.
 */
function parse_register() {
    const raw = register_input.value;
    if (raw.length !== 25) {
        show_error(`Состояние регистра должно содержать ровно 25 бит (сейчас: ${raw.length})`);
        return null;
    }
    if (/[^01]/.test(raw)) {
        show_error('Состояние регистра может содержать только 0 и 1');
        return null;
    }
    if (!/1/.test(raw)) {
        show_error('Регистр не может быть полностью нулевым — LFSR зациклится');
        return null;
    }
    return raw.split('').map(Number);
}


// ===== Фильтрация ввода регистра (только 0 и 1) =====
register_input.addEventListener('input', () => {
    const cursor_pos = register_input.selectionStart;
    const before = register_input.value;
    const filtered = before.replace(/[^01]/g, '');

    if (filtered !== before) {
        register_input.value = filtered;

        // Сохраняем позицию курсора (с учётом удалённых символов)
        const diff = before.length - filtered.length;
        register_input.setSelectionRange(cursor_pos - diff, cursor_pos - diff);
    }
});


// ===== Выбор файла =====
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


// ===== Шифрование / Дешифрование (операция одинаковая — XOR) =====
function process_file() {
    hide_error();

    // Валидируем регистр
    const register_state = parse_register();
    if (!register_state) return;

    // Проверяем файл
    if (!loaded_file_bytes || loaded_file_bytes.length === 0) {
        show_error('Сначала выберите файл');
        return;
    }

    // Выполняем шифрование / дешифрование
    const { result_bytes, key_bits, source_bits, result_bits } = lfsr_process(loaded_file_bytes, register_state);

    // Сохраняем результат
    last_result_bytes = result_bytes;

    // Выводим на экран
    key_output.textContent = format_bits(key_bits);
    source_output.textContent = format_bits(source_bits);
    result_output.textContent = format_bits(result_bits);
    output_section.style.display = 'block';
}

btn_encrypt.addEventListener('click', () => {
    is_decrypted = false;
    prev_extantion = (loaded_file_name.split(".")[1] || prev_extantion);
    process_file();
});
btn_decrypt.addEventListener('click', () => {
    is_decrypted = true;
    process_file();
});


// ===== Очистить =====
btn_clear.addEventListener('click', () => {
    hide_error();
    register_input.value = '';
    loaded_file_bytes = null;
    loaded_file_name = '';
    last_result_bytes = null;
    file_name_label.textContent = 'файл не выбран';
    key_output.textContent = '';
    source_output.textContent = '';
    result_output.textContent = '';
    output_section.style.display = 'none';
});


// ===== Сохранить результат на диск =====
btn_save.addEventListener('click', () => {
    if (!last_result_bytes) {
        show_error('Нет результата для сохранения. Сначала зашифруйте или дешифруйте файл.');
        return;
    }
    hide_error();

    // Формируем имя выходного файла
    let output_name = 'result_' + (loaded_file_name?.split(".")[0] || 'output');
    if (is_decrypted) { output_name += "." + prev_extantion; }

    // Сохраняем как поток байтов
    const blob = new Blob([last_result_bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = output_name;
    a.click();
    URL.revokeObjectURL(url);
});

import { vigenere_ru } from './ciphers/vigenereCipher.js';
import { playfair_en } from './ciphers/playfairCipher.js';

const cipher_titles = document.querySelectorAll('.cipher-title');
const user_key = document.getElementById('user_key');
const original_text = document.getElementById('original_text');
const processed_text = document.getElementById('processed_text');
const error_messages = document.querySelector('.error-messages')

const file_input = document.getElementById('file_input');
const btn_read_from_file = document.querySelector('.btn-read-from-file');
const btn_encrypt = document.querySelector('.action-btn-encrypt');
const btn_decrypt = document.querySelector('.action-btn-decrypt');
const btn_clear = document.querySelector('.action-btn-clear');
const btn_save = document.getElementById('btn_save');


cipher_titles.forEach((title) => {
    title.addEventListener('click', () => {
        cipher_titles.forEach((t) => t.classList.remove('active'));
        title.classList.add('active');
    });
});

const check_on_alphabet = (text, abc) => {
    if (abc === "ru") {
        if (/[^А-ЯЁ]/i.test(text)) {
            error_messages.textContent = "Предупреждение: можете потерять символы. Требуется русский алфавит"
            if (!error_messages.classList.contains('active')) {
                error_messages.classList.add('active');
            }
        }
        return text.replace(/[^А-ЯЁ]/gi, '');
    } else {
        if (/[^A-Z]/i.test(text)) {
            error_messages.textContent = "Предупреждение: можете потерять символы. Требуется английский алфавит"
            if (!error_messages.classList.contains('active')) {
                error_messages.classList.add('active');
            }
        }
        return text.replace(/[^A-Z]/gi, '');
    }
}

const get_choosed_method = () => {
    let selected_id = null;
    try {
        cipher_titles.forEach(title => {
            if (title.classList.contains('active')) {
                selected_id = title.id;
            }
        })
        return selected_id;
    } catch (error) {
        console.error(error);
    }
}

const choose_methods = [
    vigenere_ru,
    playfair_en
];

btn_read_from_file?.addEventListener('click', () => {
    file_input?.click();
});

file_input?.addEventListener('change', () => {
    const file = file_input.files?.[0];

    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.txt')) {
        error_messages.textContent = 'Выберите файл с расширением .txt';
        error_messages.classList.add('active');
        return;
    }

    const reader = new FileReader();
    reader.onload = () => {
        original_text.value = reader.result ?? '';
        error_messages.textContent = '';
        error_messages.classList.remove('active');
    };
    reader.readAsText(file, 'UTF-8');
    file_input.value = '';
});

btn_encrypt?.addEventListener('click', () => {
    const method_id = get_choosed_method();

    let key = user_key.value;
    let inputed_text = original_text.value;
    error_messages.textContent = "";
    error_messages.classList.remove('active');

    if (method_id === "0") {
        key = check_on_alphabet(key, "ru");
        inputed_text = check_on_alphabet(inputed_text, "ru");
    } else {
        key = check_on_alphabet(key, "eng");
        inputed_text = check_on_alphabet(inputed_text, "eng");
    }

    const encrypted_text = choose_methods[method_id](inputed_text, key, false);
    processed_text.value = encrypted_text;
});

btn_decrypt?.addEventListener('click', () => {
    const method_id = get_choosed_method();

    let key = user_key.value;
    let inputed_text = original_text.value;
    error_messages.textContent = "";
    error_messages.classList.remove('active');

    if (method_id === "0") {
        key = check_on_alphabet(key, "ru");
        inputed_text = check_on_alphabet(inputed_text, "ru");
    } else {
        key = check_on_alphabet(key, "eng");
        inputed_text = check_on_alphabet(inputed_text, "eng");
    }

    const decrypted_text = choose_methods[method_id](inputed_text, key, true);
    processed_text.value = decrypted_text;
});

btn_clear?.addEventListener('click', () => {
    error_messages.textContent = "";
    error_messages.classList.remove('active');
    user_key.value = "";
    original_text.value = "";
    processed_text.value = "";
});

btn_save?.addEventListener('click', () => {
    const text = processed_text.value;
    if (!text.trim()) {
        error_messages.textContent = 'Нет текста для сохранения';
        error_messages.classList.add('active');
        return;
    }
    error_messages.textContent = '';
    error_messages.classList.remove('active');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'processed_text.txt';
    a.click();
    URL.revokeObjectURL(url);
});

const user_key = document.getElementById('user_key');
const original_text = document.getElementById('original_text');
const encrypted_text = document.getElementById('encrypted_text');

const btn_read_from_file = document.querySelector('.btn-read-from-file');
const btn_encrypt = document.querySelector('.action-btn-encrypt');
const btn_decrypt = document.querySelector('.action-btn-decrypt');
const btn_clear = document.querySelector('.action-btn-clear');


btn_read_from_file.addEventListener('click', () => {
    console.log('btn_read_from_file clicked');
});

btn_encrypt.addEventListener('click', () => {
    console.log('btn_encrypt clicked');
});

btn_decrypt.addEventListener('click', () => {
    console.log('btn_decrypt clicked');
});

btn_clear.addEventListener('click', () => {
    console.log('btn_clear clicked');
});
export const vigenere_ru = (text, key, decrypt = false) => {
    const abc = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    let j = 0;
    
    return text.toUpperCase().replace(/[А-ЯЁ]/g, char => {
        const shift = abc.indexOf(key[j++ % key.length].toUpperCase()) * (decrypt ? -1 : 1);
        return abc[(abc.indexOf(char) + shift + 33) % 33];
    });
};

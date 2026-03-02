export const vigenere_ru = (text, key, decrypt = false) => {
    const abc = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    let j = 0;
    
    return text.toUpperCase().replace(/[А-ЯЁ]/g, char => {
        let i = ~~(j / key.length);
        const shift = abc.indexOf(abc[abc.indexOf(key[j++ % key.length].toUpperCase()) + i]) * (decrypt ? -1 : 1);
        return abc[(abc.indexOf(char) + shift + 33) % 33];
    });
};

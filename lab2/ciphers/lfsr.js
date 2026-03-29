// ==============================
//  LFSR (Linear Feedback Shift Register)
//  Размерность регистра: 25
//  Примитивный полином: x^25 + x^3 + 1
// ==============================

/**
 * Один шаг LFSR.
 * Возвращает выходной бит и обновлённое состояние регистра.
 *
 * @param {number[]} state - массив из 25 бит (0 или 1)
 * @returns {{ bit: number, state: number[] }}
 */
function lfsr_step(state) {
    // Выходной бит - последний элемент регистра
    const output_bit = state[24];

    // Обратная связь: XOR битов на позициях 25 и 3
    const feedback = state[24] ^ state[2];

    // Сдвигаем регистр вправо
    const new_state = new Array(25);
    new_state[0] = feedback;
    for (let i = 1; i < 25; i++) {
        new_state[i] = state[i - 1];
    }

    return { bit: output_bit, state: new_state };
}

/**
 * Генерирует ключевую последовательность заданной длины (в битах).
 *
 * @param {number[]} initial_state - начальное состояние регистра (25 бит)
 * @param {number} length_bits - количество бит для генерации
 * @returns {number[]} массив из 0 и 1
 */
export function generate_key_stream(initial_state, length_bits) {
    const key_stream = [];
    let current_state = [...initial_state];

    for (let i = 0; i < length_bits; i++) {
        const result = lfsr_step(current_state);
        key_stream.push(result.bit);
        current_state = result.state;
    }

    return key_stream;
}

/**
 * Переводит массив байтов в массив бит.
 *
 * @param {Uint8Array} bytes
 * @returns {number[]} массив из 0 и 1
 */
export function bytes_to_bits(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let b = 7; b >= 0; b--) {
            bits.push((bytes[i] >> b) & 1);
        }
    }
    return bits;
}

/**
 * Переводит массив бит обратно в массив байтов.
 *
 * @param {number[]} bits
 * @returns {Uint8Array}
 */
export function bits_to_bytes(bits) {
    const byte_count = Math.ceil(bits.length / 8);
    const result = new Uint8Array(byte_count);

    for (let i = 0; i < bits.length; i++) {
        const byte_index = Math.floor(i / 8);
        const bit_position = 7 - (i % 8);
        result[byte_index] |= bits[i] << bit_position;
    }

    return result;
}

/**
 * XOR двух массивов бит одинаковой длины.
 *
 * @param {number[]} data_bits
 * @param {number[]} key_bits
 * @returns {number[]}
 */
export function xor_bits(data_bits, key_bits) {
    const result = new Array(data_bits.length);
    for (let i = 0; i < data_bits.length; i++) {
        result[i] = data_bits[i] ^ key_bits[i];
    }
    return result;
}

/**
 * Шифрование / дешифрование файла (потоковый шифр - операция идентична).
 *
 * @param {Uint8Array} file_bytes - байты исходного файла
 * @param {number[]} register_state - начальное состояние LFSR (25 бит)
 * @returns {{ result_bytes: Uint8Array, key_bits: number[], source_bits: number[], result_bits: number[] }}
 */
export function lfsr_process(file_bytes, register_state) {
    const source_bits = bytes_to_bits(file_bytes);
    const key_bits = generate_key_stream(register_state, source_bits.length);
    const result_bits = xor_bits(source_bits, key_bits);
    const result_bytes = bits_to_bytes(result_bits);

    return { result_bytes, key_bits, source_bits, result_bits };
}

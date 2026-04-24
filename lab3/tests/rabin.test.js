/**
 * Модульные тесты для функций криптосистемы Рабина.
 * Использует встроенный в Node.js тестовый раннер с assertions.
 */

import { mod, euclidEx, fastExp, isPrime, validateParams, encryptBytes, decryptValues } from '../ciphers/rabin.js';
import assert from 'assert';

// ===== Тестируем функцию mod() =====
console.log('Тестируем функцию mod()...');

// Тестируем положительные числа
assert.strictEqual(mod(10n, 3n), 1n, 'mod(10, 3) должен быть 1');
assert.strictEqual(mod(0n, 5n), 0n, 'mod(0, 5) должен быть 0');
assert.strictEqual(mod(7n, 7n), 0n, 'mod(7, 7) должен быть 0');

// Тестируем отрицательные числа - должен возвращаться неотрицательный результат
assert.strictEqual(mod(-1n, 5n), 4n, 'mod(-1, 5) должен быть 4');
assert.strictEqual(mod(-10n, 3n), 2n, 'mod(-10, 3) должен быть 2');
assert.strictEqual(mod(-7n, 7n), 0n, 'mod(-7, 7) должен быть 0');

console.log('Тесты mod() пройдены\n');

// ===== Тестируем функцию euclidEx() (Расширенный алгоритм Евклида) =====
console.log('Тестируем функцию euclidEx()...');

// Базовый случай: gcd(48, 18) = 6, и 48*(-3) + 18*8 = 6
const result1 = euclidEx(48n, 18n);
assert.strictEqual(result1.d, 6n, 'gcd(48, 18) должен быть 6');
// Проверяем: 48*x + 18*y = 6
assert.strictEqual(48n * result1.x + 18n * result1.y, 6n, 'Тождество Безу должно выполняться');

// Взаимно простые числа: gcd(35, 12) = 1
const result2 = euclidEx(35n, 12n);
assert.strictEqual(result2.d, 1n, 'gcd(35, 12) должен быть 1');
assert.strictEqual(35n * result2.x + 12n * result2.y, 1n, 'Тождество Безу должно выполняться');

// Одно число кратное другому
const result3 = euclidEx(100n, 20n);
assert.strictEqual(result3.d, 20n, 'gcd(100, 20) должен быть 20');

console.log('Тесты euclidEx() пройдены\n');

// ===== Тестируем функцию fastExp() (Модульное возведение в степень) =====
console.log('Тестируем функцию fastExp()...');

// Базовые случаи
assert.strictEqual(fastExp(2n, 3n, 5n), 3n, '2^3 mod 5 = 8 mod 5 = 3');
assert.strictEqual(fastExp(3n, 4n, 7n), 4n, '3^4 mod 7 = 81 mod 7 = 4');
assert.strictEqual(fastExp(5n, 0n, 13n), 1n, 'Любое^0 mod n = 1');
assert.strictEqual(fastExp(2n, 10n, 100n), 24n, '2^10 mod 100 = 1024 mod 100 = 24');

// Основание больше модуля
assert.strictEqual(fastExp(10n, 2n, 3n), 1n, '10^2 mod 3 = 100 mod 3 = 1');

console.log('Тесты fastExp() пройдены\n');

// ===== Тестируем функцию isPrime() =====
console.log('Тестируем функцию isPrime()...');

// Маленькие простые числа
assert.strictEqual(isPrime(2n), true, '2 это простое');
assert.strictEqual(isPrime(3n), true, '3 это простое');
assert.strictEqual(isPrime(5n), true, '5 это простое');
assert.strictEqual(isPrime(7n), true, '7 это простое');
assert.strictEqual(isPrime(11n), true, '11 это простое');
assert.strictEqual(isPrime(13n), true, '13 это простое');

// Маленькие составные числа
assert.strictEqual(isPrime(1n), false, '1 не простое');
assert.strictEqual(isPrime(4n), false, '4 не простое');
assert.strictEqual(isPrime(6n), false, '6 не простое');
assert.strictEqual(isPrime(8n), false, '8 не простое');
assert.strictEqual(isPrime(9n), false, '9 не простое');
assert.strictEqual(isPrime(10n), false, '10 не простое');

// Большие простые числа (часто используемые в Рабине)
assert.strictEqual(isPrime(7n), true, '7 ≡ 3 mod 4 простое');
assert.strictEqual(isPrime(11n), true, '11 ≡ 3 mod 4 простое');
assert.strictEqual(isPrime(19n), true, '19 ≡ 3 mod 4 простое');
assert.strictEqual(isPrime(23n), true, '23 ≡ 3 mod 4 простое');

// Не простые
assert.strictEqual(isPrime(15n), false, '15 = 3*5 не простое');
assert.strictEqual(isPrime(21n), false, '21 = 3*7 не простое');
assert.strictEqual(isPrime(25n), false, '25 = 5^2 не простое');

console.log('Тесты isPrime() пройдены\n');

// ===== Тестируем функцию validateParams() =====
console.log('Тестируем функцию validateParams()...');

// Верные параметры: p=7, q=11, b=5 (оба ≡ 3 mod 4, n=77 > 256? НЕТ! должена ошибка)
try {
    validateParams(7n, 11n, 5n);
    assert.fail('Должна быть ошибка: n=77 не > 256');
} catch (e) {
    assert.match(e.message, /256/, 'Должна быть ошибка про n > 256');
}

// Верные параметры с n > 256
// p=17 (≡ 1 mod 4) - должна ошибка
try {
    validateParams(17n, 19n, 5n);
    assert.fail('Должна быть ошибка: p=17 не ≡ 3 mod 4');
} catch (e) {
    assert.match(e.message, /mod 4/, 'Должна быть ошибка про mod 4');
}

// p=19 (≡ 3 mod 4), q=23 (≡ 3 mod 4), n=437 > 256, b=100 (верно)
const n = validateParams(19n, 23n, 100n);
assert.strictEqual(n, 437n, 'n должен быть 19*23 = 437');

// p и q одинаковые - должна ошибка
try {
    validateParams(19n, 19n, 100n);
    assert.fail('Должна быть ошибка: p и q должны различаться');
} catch (e) {
    assert.match(e.message, /разн/, 'Должна быть ошибка про разные простые');
}

// b вне диапазона
try {
    validateParams(19n, 23n, 0n);
    assert.fail('Должна быть ошибка: b должен быть > 0');
} catch (e) {
    assert.match(e.message, /0/, 'Должна быть ошибка про диапазон b');
}

try {
    validateParams(19n, 23n, 437n);
    assert.fail('Должна быть ошибка: b должен быть < n');
} catch (e) {
    assert.match(e.message, /0/, 'Должна быть ошибка про диапазон b');
}

console.log('Тесты validateParams() пройдены\n');

// ===== Тестируем функции encryptBytes() и decryptValues() =====
console.log('Тестируем функции encryptBytes() и decryptValues()...');

// Используем параметры с n > 65535 чтобы m' = m*257 помещалось в n
// p=251 (≡ 3 mod 4), q=263 (≡ 3 mod 4), n=66013 > 65535
const testP = 251n;
const testQ = 263n;
const testB = 100n;
const testN = testP * testQ; // 66013

// Тестируем с простым массивом байтов
const originalBytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
const encrypted = encryptBytes(originalBytes, testN, testB);

// Проверяем что зашифрованные значения отличаются от оригинала
assert.strictEqual(encrypted.length, originalBytes.length, 'Длина зашифрованного должна совпадать с входной');
for (let i = 0; i < originalBytes.length; i++) {
    assert.notStrictEqual(Number(encrypted[i]), originalBytes[i], `Зашифрованное значение должно отличаться от оригинала на индексе ${i}`);
}

// Расшифровываем и проверяем что получили исходные байты
const decrypted = decryptValues(encrypted, testP, testQ, testB);
assert.deepStrictEqual(decrypted, originalBytes, 'Расшифрованные байты должны совпадать с оригинальными');

// Тестируем со всеми возможными значениями байтов (0-255)
const allBytes = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
    allBytes[i] = i;
}
const encryptedAll = encryptBytes(allBytes, testN, testB);
const decryptedAll = decryptValues(encryptedAll, testP, testQ, testB);
assert.deepStrictEqual(decryptedAll, allBytes, 'Круговой должен работать для всех значений байтов (0-255)');

console.log('Тесты encryptBytes() и decryptValues() пройдены\n');

// ===== Тестируем граничные случаи =====
console.log('Тестируем граничные случаи...');

// Тестируем с одним байтом
const singleByte = new Uint8Array([0]);
const encryptedSingle = encryptBytes(singleByte, testN, testB);
const decryptedSingle = decryptValues(encryptedSingle, testP, testQ, testB);
assert.deepStrictEqual(decryptedSingle, singleByte, 'Должен обрабатывать значение байта 0');

// Тестируем с максимальным значением байта
const maxByte = new Uint8Array([255]);
const encryptedMax = encryptBytes(maxByte, testN, testB);
const decryptedMax = decryptValues(encryptedMax, testP, testQ, testB);
assert.deepStrictEqual(decryptedMax, maxByte, 'Должен обрабатывать значение байта 255');

// Тестируем пустой массив
const emptyBytes = new Uint8Array(0);
const encryptedEmpty = encryptBytes(emptyBytes, testN, testB);
assert.strictEqual(encryptedEmpty.length, 0, 'Зашифрованный пустой массив должен быть пустым');
const decryptedEmpty = decryptValues(encryptedEmpty, testP, testQ, testB);
assert.strictEqual(decryptedEmpty.length, 0, 'Расшифрованный пустой массив должен быть пустым');

console.log('Тесты граничных случаев пройдены\n');

// ===== Все тесты пройдены =====
console.log('========================================');
console.log('Все тесты Рабина пройдены!');
console.log('========================================');

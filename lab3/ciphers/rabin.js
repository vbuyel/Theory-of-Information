/**
 * Вычисляет a по модулю n, гарантируя неотрицательный результат.
 * @param {bigint} a - Делимое.
 * @param {bigint} n - Делитель (должен быть положительным).
 * @returns {bigint} Остаток в диапазоне [0, n-1].
 */
export function mod(a, n) {
  const r = a % n;
  return r >= 0n ? r : r + n;
}

/**
 * Расширенный алгоритм Евклида.
 * Находит целые числа x, y такие, что a*x + b*y = gcd(a, b).
 * @param {bigint} a - Первое число.
 * @param {bigint} b - Второе число.
 * @returns {{ x: bigint, y: bigint, d: bigint }} Коэффициенты и НОД.
 */
export function euclidEx(a, b) {
  let remainderOld = a;
  let remainderNew = b;
  let coeffXOld = 1n;
  let coeffXNew = 0n;
  let coeffYOld = 0n;
  let coeffYNew = 1n;

  while (remainderNew !== 0n) {
    const quotient = remainderOld / remainderNew;
    const remainderTemp = remainderOld % remainderNew;
    const coeffXTemp = coeffXOld - quotient * coeffXNew;
    const coeffYTemp = coeffYOld - quotient * coeffYNew;

    remainderOld = remainderNew;
    remainderNew = remainderTemp;
    coeffXOld = coeffXNew;
    coeffXNew = coeffXTemp;
    coeffYOld = coeffYNew;
    coeffYNew = coeffYTemp;
  }

  return { x: coeffXOld, y: coeffYOld, d: remainderOld };
}

/**
 * Быстрое модульное возведение в степень методом "квадрат и умножение".
 * Вычисляет (a^z) mod n эффективно.
 * @param {bigint} a - Основание.
 * @param {bigint} z - Показатель степени (неотрицательный).
 * @param {bigint} n - Модуль (положительный).
 * @returns {bigint} (a^z) mod n.
 */
export function fastExp(a, z, n) {
  let base = mod(a, n);
  let exponent = z;
  let result = 1n;

  while (exponent !== 0n) {
    // Пока показатель чётный, возводим в квадрат и делим пополам
    while (exponent % 2n === 0n) {
      exponent /= 2n;
      base = mod(base * base, n);
    }
    exponent -= 1n;
    result = mod(result * base, n);
  }

  return result;
}

/**
 * Проверка числа на простоту методом пробного деления.
 * Подходит для small to medium-sized чисел, используемых в этой лабораторной.
 * @param {bigint} n - Число для проверки.
 * @returns {boolean} True, если n простое, иначе false.
 */
export function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  // Проверяем нечётные делители до sqrt(n)
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

/**
 * Избыточность: дублируем байт чтобы шифротексты имели совпадающие старший/младший байты.
 * m' = m * 256 + m, поэтому при расшифровке проверяем (m' >> 8) == (m' & 255).
 * @constant {bigint}
 */
const REDUNDANCY_MULTIPLIER = 257n; // 256 + 1

/**
 * Проверяет параметры криптосистемы Рабина.
 * Требования: p и q должны быть разными простыми числами ≡ 3 (mod 4),
 * n = p*q должен быть > 256 (для шифрования байтов), и 0 < b < n.
 * @param {bigint} p - Первый простой параметр.
 * @param {bigint} q - Второй простой параметр.
 * @param {bigint} b - Дополнительный параметр.
 * @returns {bigint} Модуль n = p * q.
 * @throws {Error} Если параметры некорректны.
 */
export function validateParams(p, q, b) {
  if (!isPrime(p) || !isPrime(q)) {
    throw new Error("p и q должны быть простыми числами.");
  }
  if (p === q) {
    throw new Error("p и q должны быть разными простыми числами.");
  }
  if (p % 4n !== 3n || q % 4n !== 3n) {
    throw new Error("Должно выполняться p ≡ q ≡ 3 (mod 4).");
  }
  const n = p * q;
  if (n <= 256n) {
    throw new Error("Требуется n = p*q > 256 для шифрования байтов.");
  }
  if (b <= 0n || b >= n) {
    throw new Error("Требуется 0 < b < n.");
  }
  return n;
}

/**
 * Шифрует массив байтов с помощью криптосистемы Рабина.
 * Для каждого байта m вычисляет m' = m * 257 (дублирование для избыточности),
 * затем c = m' * (m' + b) mod n.
 * @param {Uint8Array} bytes - Байты для шифрования.
 * @param {bigint} n - Модуль (p * q).
 * @param {bigint} b - Параметр шифрования.
 * @returns {bigint[]} Массив зашифрованных значений.
 */
export function encryptBytes(bytes, n, b) {
  const encrypted = [];
  for (const byte of bytes) {
    const m = BigInt(byte) * REDUNDANCY_MULTIPLIER; // m' = m * 257
    const c = mod(m * (m + b), n);
    encrypted.push(c);
  }
  return encrypted;
}

/**
 * Вычисляет квадратные корни по модулю n = p*q с помощью китайской теоремы об остатках.
 * Так как p, q ≡ 3 (mod 4), sqrt вычисляется как: m = ±(D^((p+1)/4)) mod p.
 * @param {bigint} D - Значение, из которого извлекается корень (по модулю n).
 * @param {bigint} p - Первое простое (≡ 3 mod 4).
 * @param {bigint} q - Второе простое (≡ 3 mod 4).
 * @returns {bigint[]} Массив из 4 возможных корней по модулю n.
 */
function sqrtModByCRT(D, p, q) {
  // Вычисляем квадратные корни по модулю p и q, используя факт что p ≡ 3 (mod 4)
  const sqrtP = fastExp(mod(D, p), (p + 1n) / 4n, p);
  const sqrtQ = fastExp(mod(D, q), (q + 1n) / 4n, q);

  // Используем расширенный алгоритм Евклида для нахождения коэффициентов КТО
  const { x: coeffP, y: coeffQ } = euclidEx(p, q);

  const n = p * q;
  // Объединяем корни с помощью КТО для получения 4 решений по модулю n
  const root1 = mod(coeffP * p * sqrtQ + coeffQ * q * sqrtP, n);
  const root2 = mod(n - root1, n);
  const root3 = mod(coeffP * p * sqrtQ - coeffQ * q * sqrtP, n);
  const root4 = mod(n - root3, n);

  return [root1, root2, root3, root4];
}

/**
 * Восстанавливает исходный байт сообщения из квадратного корня.
 * Решает: m = (di - b) / 2 mod n для исходного сообщения.
 * Так как работаем по нечётному модулю n, 2 имеет модульный обратный.
 * @param {bigint} root - Квадратный корень из (b^2 + 4c) mod n.
 * @param {bigint} b - Параметр шифрования.
 * @param {bigint} n - Модуль (должен быть нечётным).
 * @returns {bigint} Восстановленное значение сообщения.
 */
function recoverMessageFromRoot(root, b, n) {
  const adjusted = mod(root - b, n);
  // Вычисляем модульный обратный 2 по модулю n (так как n нечётный, gcd(2,n)=1)
  // 2^(-1) mod n = (n+1)/2 когда n нечётное
  const inv2 = (n + 1n) / 2n;
  return mod(adjusted * inv2, n);
}

/**
 * Расшифровывает одно зашифрованное значение и возвращает исходный байт.
 * Пробует все 4 возможных квадратных корня, проверяет повторным шифрованием,
 * и учитывает смещение избыточности (256), добавленное при шифровании.
 * @param {bigint} ciphertext - Зашифрованное значение.
 * @param {bigint} p - Первое простое.
 * @param {bigint} q - Второе простое.
 * @param {bigint} b - Параметр шифрования.
 * @returns {number} Расшифрованный байт (0-255).
 * @throws {Error} Если не удалось восстановить байт.
 */
function decryptValue(ciphertext, p, q, b) {
  const n = p * q;
  const discriminant = mod(b * b + 4n * ciphertext, n);
  const roots = sqrtModByCRT(discriminant, p, q);

  for (const root of roots) {
    const messageWithRedundancy = recoverMessageFromRoot(root, b, n);
    // Проверяем равенство старшего и младшего байта (проверка избыточности: m' = m*256 + m)
    const lowByte = messageWithRedundancy & 255n;
    const highByte = messageWithRedundancy >> 8n;
    if (lowByte === highByte && messageWithRedundancy >= 0n) {
      // Проверяем повторным шифрованием
      const reEncrypted = mod(messageWithRedundancy * (messageWithRedundancy + b), n);
      if (reEncrypted === ciphertext && lowByte <= 255n) {
        return Number(lowByte);
      }
    }
  }

  throw new Error(`Не удалось однозначно восстановить байт для c=${ciphertext.toString()}.`);
}

/**
 * Расшифровывает массив зашифрованных значений обратно в исходные байты.
 * @param {bigint[]} values - Массив зашифрованных значений (BigInt).
 * @param {bigint} p - Первый простой параметр.
 * @param {bigint} q - Второй простой параметр.
 * @param {bigint} b - Параметр шифрования.
 * @returns {Uint8Array} Расшифрованные байты.
 */
export function decryptValues(values, p, q, b) {
  const out = new Uint8Array(values.length);
  for (let i = 0; i < values.length; i += 1) {
    out[i] = decryptValue(values[i], p, q, b);
  }
  return out;
}

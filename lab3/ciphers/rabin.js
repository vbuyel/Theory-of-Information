export function mod(a, n) {
  const r = a % n;
  return r >= 0n ? r : r + n;
}

export function euclidEx(a, b) {
  let d0 = a;
  let d1 = b;
  let x0 = 1n;
  let x1 = 0n;
  let y0 = 0n;
  let y1 = 1n;

  while (d1 !== 0n) {
    const q = d0 / d1;
    const d2 = d0 % d1;
    const x2 = x0 - q * x1;
    const y2 = y0 - q * y1;

    d0 = d1;
    d1 = d2;
    x0 = x1;
    x1 = x2;
    y0 = y1;
    y1 = y2;
  }

  return { x: x0, y: y0, d: d0 };
}

export function fastExp(a, z, n) {
  let a1 = mod(a, n);
  let z1 = z;
  let x = 1n;

  while (z1 !== 0n) {
    while (z1 % 2n === 0n) {
      z1 /= 2n;
      a1 = mod(a1 * a1, n);
    }
    z1 -= 1n;
    x = mod(x * a1, n);
  }

  return x;
}

export function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

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

export function encryptBytes(bytes, n, b) {
  const encrypted = [];
  for (const byte of bytes) {
    const m = BigInt(byte);
    const c = mod(m * (m + b), n);
    encrypted.push(c);
  }
  return encrypted;
}

function sqrtModByCRT(D, p, q) {
  const mp = fastExp(mod(D, p), (p + 1n) / 4n, p);
  const mq = fastExp(mod(D, q), (q + 1n) / 4n, q);

  const { x: yp, y: yq, d } = euclidEx(p, q);
  if (d !== 1n) {
    throw new Error("p и q должны быть взаимно просты.");
  }

  const n = p * q;
  const d1 = mod(yp * p * mq + yq * q * mp, n);
  const d2 = mod(n - d1, n);
  const d3 = mod(yp * p * mq - yq * q * mp, n);
  const d4 = mod(n - d3, n);
  return [d1, d2, d3, d4];
}

function recoverMessageFromRoot(di, b, n) {
  const t = mod(di - b, n);
  if (t % 2n === 0n) {
    return mod(t / 2n, n);
  }
  return mod((t + n) / 2n, n);
}

function decryptValue(ci, p, q, b) {
  const n = p * q;
  const D = mod(b * b + 4n * ci, n);
  const roots = sqrtModByCRT(D, p, q);

  for (const di of roots) {
    const m = recoverMessageFromRoot(di, b, n);
    if (m >= 0n && m <= 255n) {
      return Number(m);
    }
  }

  throw new Error(`Не удалось однозначно восстановить байт для c=${ci.toString()}.`);
}

export function decryptValues(values, p, q, b) {
  const out = new Uint8Array(values.length);
  for (let i = 0; i < values.length; i += 1) {
    out[i] = decryptValue(values[i], p, q, b);
  }
  return out;
}

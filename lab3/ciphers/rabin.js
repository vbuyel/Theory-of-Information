/**
 * rabin.js — Rabin Cryptosystem: encryption / decryption
 *
 * Encryption formula:
 *   C = m * (m + b) mod n
 *
 * Padding strategy — 2-byte marker (0xFF 0xFF)
 *   Before encrypting each block, two bytes 0xFF 0xFF are appended.
 *   After decryption, the correct root (out of 4 CRT candidates) is
 *   identified as the one whose trailing 2 bytes equal the marker.
 *
 * Block layout
 *   n = p * q determines maximum block value.
 *   blockSize  = byte-length of (n − 1), minus 2 bytes reserved for the marker.
 *   Each plaintext chunk of `blockSize` bytes is concatenated with 0xFF 0xFF,
 *   converted to a BigInt, encrypted, and stored as a fixed-width BigInt
 *   occupying `cipherBlockSize` bytes (byte-length of n).
 */

import { mod, gcdExtended, power, isPrime } from './math.js';


/* ------------------------------------------------------------------ */
/*  Marker constants                                                   */
/* ------------------------------------------------------------------ */
const MARKER = new Uint8Array([0xFF, 0xFF]);
const MARKER_LEN = MARKER.length;            // 2


/* ------------------------------------------------------------------ */
/*  Helpers: BigInt ↔ byte-array conversions (big-endian)              */
/* ------------------------------------------------------------------ */


/**
 * Return how many bytes are needed to represent value (≥ 1).
 * @param {bigint} value
 * @returns {number}
 */
function byteLength(value) {
    if (value <= 0n) return 1;
    let len = 0;
    let v = value;
    while (v > 0n) { v >>= 8n; len++; }
    return len;
}


/**
 * BigInt → Uint8Array (big-endian), zero-padded to `len` bytes.
 */
function bigintToBytes(value, len) {
    const bytes = new Uint8Array(len);
    let v = value;
    for (let i = len - 1; i >= 0; i--) {
        bytes[i] = Number(v & 0xFFn);
        v >>= 8n;
    }
    return bytes;
}


/**
 * Uint8Array (big-endian) → BigInt.
 */
function bytesToBigint(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}


/* ------------------------------------------------------------------ */
/*  Parameter validation                                               */
/* ------------------------------------------------------------------ */


/**
 * Validate Rabin parameters p, q, b.
 *
 * Checks:
 *   - p and q are prime
 *   - p ≡ 3 (mod 4) and q ≡ 3 (mod 4)
 *   - p ≠ q
 *   - 0 < b < n
 *
 * @param {bigint} p
 * @param {bigint} q
 * @param {bigint} b
 * @returns {{ valid: boolean, error?: string, n?: bigint }}
 */
export function validateParams(p, q, b) {
    if (!isPrime(p)) return { valid: false, error: 'p не является простым числом' };
    if (!isPrime(q)) return { valid: false, error: 'q не является простым числом' };
    if (p % 4n !== 3n) return { valid: false, error: 'p должно быть ≡ 3 (mod 4)' };
    if (q % 4n !== 3n) return { valid: false, error: 'q должно быть ≡ 3 (mod 4)' };
    if (p === q) return { valid: false, error: 'p и q должны быть различными' };

    const n = p * q;

    // n must be large enough so that (1 data byte ‖ 0xFF 0xFF) as BigInt < n
    // worst case: 0xFF 0xFF 0xFF = 16 777 215, so n must be > 16 777 215
    const MIN_N = (1n << 24n);  // 16 777 216
    if (n < MIN_N) return { valid: false, error: `n = p·q слишком мало (нужно n ≥ ${MIN_N}, сейчас n = ${n})` };
    if (b <= 0n || b >= n) return { valid: false, error: 'b должно быть в диапазоне 0 < b < n' };

    return { valid: true, n };
}


/* ------------------------------------------------------------------ */
/*  Encryption                                                         */
/* ------------------------------------------------------------------ */


/**
 * Encrypt arbitrary binary data with the Rabin cryptosystem.
 *
 * @param {Uint8Array} data — plaintext bytes
 * @param {bigint} b
 * @param {bigint} n  — public key n = p·q
 * @returns {Uint8Array} — ciphertext (concatenation of fixed-width cipher blocks)
 */
export function rabinEncrypt(data, b, n) {
    const nBytes = byteLength(n);

    // Find the largest number of data bytes k such that the worst-case
    // padded value  (k+2 bytes, all 0xFF) = 256^(k+2) − 1  is still < n.
    // This guarantees every padded message m < n.
    let blockSize = 0;
    for (let k = 1; k <= nBytes; k++) {
        // worst-case padded value with k data bytes:  (256^(k + MARKER_LEN)) - 1
        const worstCase = (1n << (BigInt(k + MARKER_LEN) * 8n)) - 1n;
        if (worstCase < n) {
            blockSize = k;
        } else {
            break;
        }
    }

    if (blockSize < 1) {
        throw new Error('n слишком мало для блочного шифрования');
    }

    const cipherBlockSize = nBytes;                          // each cipher block = nBytes
    const blockCount = Math.ceil(data.length / blockSize);
    const out = new Uint8Array(blockCount * cipherBlockSize);

    for (let i = 0; i < blockCount; i++) {
        // 1. Extract plaintext chunk (may be shorter than blockSize for the last block)
        const start = i * blockSize;
        const end = Math.min(start + blockSize, data.length);
        const chunk = data.slice(start, end);

        // 2. Append marker: chunk ‖ 0xFF 0xFF
        const padded = new Uint8Array(chunk.length + MARKER_LEN);
        padded.set(chunk, 0);
        padded.set(MARKER, chunk.length);

        // 3. Convert to BigInt  m
        const m = bytesToBigint(padded);

        // Safety check (should never trigger with correct blockSize)
        if (m >= n) {
            throw new Error(`Блок ${i + 1}: m (${m}) >= n (${n}), невозможно зашифровать`);
        }

        // 4. Encrypt:  c = m·(m + b) mod n
        const c = mod(m * (m + b), n);

        // 5. Write cipher block (fixed width)
        const cBytes = bigintToBytes(c, cipherBlockSize);
        out.set(cBytes, i * cipherBlockSize);
    }

    return out;
}


/* ------------------------------------------------------------------ */
/*  Decryption                                                         */
/* ------------------------------------------------------------------ */


/**
 * Decrypt Rabin ciphertext back to plaintext.
 *
 * For each cipher block:
 *   1. Compute discriminant D = b² + 4c (mod n)
 *   2. Square roots mod p, mod q  (possible because p,q ≡ 3 mod 4)
 *   3. CRT → 4 candidate roots  r1…r4
 *   4. For each root:  m_candidate = (−b + root) / 2  mod n
 *      (division by 2 is modular inverse)
 *   5. Pick the candidate whose byte representation ends with 0xFF 0xFF
 *
 * @param {Uint8Array} cipherData
 * @param {bigint} b
 * @param {bigint} n
 * @param {bigint} p
 * @param {bigint} q
 * @returns {Uint8Array} — recovered plaintext
 */
export function rabinDecrypt(cipherData, b, n, p, q) {
    const nBytes = byteLength(n);
    const cipherBlockSize = nBytes;
    const blockCount = cipherData.length / cipherBlockSize;

    if (!Number.isInteger(blockCount) || blockCount === 0) {
        throw new Error('Некорректная длина шифротекста');
    }

    // Pre-compute CRT coefficients  (only once)
    const { x: yp, y: yq } = gcdExtended(p, q);   // p·yp + q·yq = 1

    // Modular inverse of 2 mod n (needed for m = (root - b) / 2 mod n)
    const inv2 = mod(power(2n, n - p - q, n), n);  // Euler-totient shortcut
    // Alternatively: inv2 = gcdExtended(2n, n).x mod n
    // Using (n+1n)/2n works when n is odd (always true for product of two odd primes)
    const inv2Simple = (n + 1n) / 2n;               // because 2·((n+1)/2) = n+1 ≡ 1 mod n

    const chunks = [];

    for (let i = 0; i < blockCount; i++) {
        const cBytes = cipherData.slice(i * cipherBlockSize, (i + 1) * cipherBlockSize);
        const c = bytesToBigint(cBytes);

        // D = b² + 4c  mod n
        const D = mod(b * b + 4n * c, n);

        // Square roots mod p and mod q  (p,q ≡ 3 mod 4 ⇒ exponent (p+1)/4)
        const mp = power(D, (p + 1n) / 4n, p);
        const mq = power(D, (q + 1n) / 4n, q);

        // CRT combination for ±mp, ±mq  →  4 roots of D mod n
        const t1 = mod(yp * p * mq, n);
        const t2 = mod(yq * q * mp, n);

        const roots = [
            mod(t1 + t2, n),
            mod(n - (t1 + t2), n),
            mod(t1 - t2, n),
            mod(n - (t1 - t2), n),
        ];

        // For each root r, candidate message = (−b + r) / 2  mod n  = (r - b) · inv2 mod n
        // The padded block is between (MARKER_LEN+1) and (nBytes-1) bytes wide.
        // We try each plausible width for the marker check.
        let found = false;
        for (const r of roots) {
            const m = mod((r - b) * inv2Simple, n);

            // Verify this candidate re-encrypts to c
            if (mod(m * (m + b), n) !== c) continue;

            // Try plausible padded widths: from max (nBytes - 1) down to min (MARKER_LEN + 1)
            const maxW = nBytes - 1;
            const minW = MARKER_LEN + 1;       // at least 1 data byte + 2 marker bytes
            for (let w = maxW; w >= minW; w--) {
                const mBytes = bigintToBytes(m, w);

                if (mBytes[w - 2] === 0xFF &&
                    mBytes[w - 1] === 0xFF) {
                    // Strip marker → original chunk
                    const plainChunk = mBytes.slice(0, w - MARKER_LEN);
                    chunks.push(plainChunk);
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            throw new Error(`Не удалось найти корректный корень для блока ${i + 1}`);
        }
    }

    // Concatenate all plaintext chunks
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}


/* ------------------------------------------------------------------ */
/*  Convenience: produce decimal-string representation of ciphertext   */
/* ------------------------------------------------------------------ */


/**
 * Convert cipher bytes to a space-separated list of decimal BigInt blocks.
 * Each cipher block is read as a BigInt and printed in base 10.
 *
 * @param {Uint8Array} cipherData
 * @param {bigint} n
 * @returns {string}
 */
export function cipherToDecimalString(cipherData, n) {
    const cipherBlockSize = byteLength(n);
    const count = cipherData.length / cipherBlockSize;
    const parts = [];
    for (let i = 0; i < count; i++) {
        const block = cipherData.slice(i * cipherBlockSize, (i + 1) * cipherBlockSize);
        parts.push(bytesToBigint(block).toString(10));
    }
    return parts.join(' ');
}


/**
 * Parse a decimal-string representation back to cipher bytes.
 *
 * @param {string} text — space-separated decimal BigInt values
 * @param {bigint} n
 * @returns {Uint8Array}
 */
export function decimalStringToCipher(text, n) {
    const cipherBlockSize = byteLength(n);
    const values = text.trim().split(/\s+/).map(s => BigInt(s));
    const out = new Uint8Array(values.length * cipherBlockSize);
    for (let i = 0; i < values.length; i++) {
        const bytes = bigintToBytes(values[i], cipherBlockSize);
        out.set(bytes, i * cipherBlockSize);
    }
    return out;
}

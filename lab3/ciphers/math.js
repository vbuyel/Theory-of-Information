/**
 * math.js — Core Mathematical Functions (BigInt-based)
 * 
 * Provides:
 *   - mod(a, n)           — non-negative modular remainder
 *   - gcdExtended(a, b)   — Extended Euclidean Algorithm (Bézout coefficients)
 *   - power(base, exp, mod) — Binary (square-and-multiply) modular exponentiation
 *   - isPrime(n)          — Trial-division primality test
 */


/**
 * Non-negative modular remainder.
 * Guarantees result in [0, n-1] even when a is negative.
 *
 * @param {bigint} a  — dividend
 * @param {bigint} n  — modulus (> 0)
 * @returns {bigint}  — a mod n ∈ [0, n-1]
 */
export function mod(a, n) {
    const r = a % n;
    return r < 0n ? r + n : r;
}


/**
 * Extended Euclidean Algorithm.
 * Finds integers x, y such that a·x + b·y = gcd(a, b).
 *
 * @param {bigint} a
 * @param {bigint} b
 * @returns {{ gcd: bigint, x: bigint, y: bigint }}
 *
 * @example
 *   gcdExtended(15n, 6n) → { gcd: 3n, x: 1n, y: -2n }
 *   // 15·1 + 6·(-2) = 3
 */
export function gcdExtended(a, b) {
    let x0 = 1n, y0 = 0n;
    let x1 = 0n, y1 = 1n;

    while (b > 0n) {
        const q = a / b;
        const r = a % b;

        a = b;
        b = r;

        const x2 = x0 - q * x1;
        const y2 = y0 - q * y1;

        x0 = x1; x1 = x2;
        y0 = y1; y1 = y2;
    }

    return { gcd: a, x: x0, y: y0 };
}


/**
 * Modular exponentiation (binary / square-and-multiply).
 * Computes  base^exp mod m  efficiently.
 *
 * @param {bigint} base
 * @param {bigint} exp   — must be ≥ 0
 * @param {bigint} m     — modulus (> 0)
 * @returns {bigint}
 *
 * @example
 *   power(2n, 10n, 1000n)  // 24n   (2^10 = 1024 mod 1000)
 */
export function power(base, exp, m) {
    let result = 1n;
    base = mod(base, m);

    while (exp > 0n) {
        if (exp & 1n) {
            result = mod(result * base, m);
        }
        base = mod(base * base, m);
        exp >>= 1n;
    }

    return result;
}


/**
 * Trial-division primality test, optimised with 6k ± 1 wheel.
 * Sufficient for the key sizes used in this lab.
 *
 * @param {bigint} n
 * @returns {boolean}
 */
export function isPrime(n) {
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;

    for (let i = 5n; i * i <= n; i += 6n) {
        if (n % i === 0n || n % (i + 2n) === 0n) {
            return false;
        }
    }
    return true;
}

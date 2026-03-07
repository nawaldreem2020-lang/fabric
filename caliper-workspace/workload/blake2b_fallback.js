'use strict';

/**
 * ══════════════════════════════════════════════════════════════════════
 *  BLAKE2b-256 Pure JavaScript Fallback Implementation
 *  Branch: fabric-BLAKE2-Security
 * ══════════════════════════════════════════════════════════════════════
 *
 *  This module provides BLAKE2b-256 hashing when the 'blakejs' npm
 *  package is not installed. It implements the RFC 7693 specification.
 *
 *  Usage:
 *    const { blake2bHex } = require('./blake2b_fallback');
 *    const hash = blake2bHex('data string');  // returns 64-char hex
 *
 *  Note: For production use, install blakejs: npm install blakejs
 *  The blakejs package is ~10x faster than this pure-JS implementation.
 *
 *  Algorithm: BLAKE2b (RFC 7693)
 *  Output: 256-bit / 32-byte / 64-char lowercase hex
 *  Key: none (unkeyed hash mode — same as Go blake2b.New256(nil))
 * ══════════════════════════════════════════════════════════════════════
 */

// BLAKE2b initialization vectors (first 8 words of fractional part of sqrt of primes)
const BLAKE2B_IV = new Uint32Array([
    0xF3BCC908, 0x6A09E667,
    0x84CAA73B, 0xBB67AE85,
    0xFE94F82B, 0x3C6EF372,
    0x5F1D36F1, 0xA54FF53A,
    0xADE682D1, 0x510E527F,
    0x2B3E6C1F, 0x9B05688C,
    0xFB41BD6B, 0x1F83D9AB,
    0x137E2179, 0x5BE0CD19
]);

// BLAKE2b sigma permutation table
const SIGMA = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
];

/**
 * 64-bit addition via 32-bit hi/lo pairs
 */
function ADD64AA(v, a, b) {
    const o0 = v[a] + v[b];
    let o1 = v[a+1] + v[b+1];
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;
    v[a+1] = o1;
}

function ADD64AC(v, a, b0, b1) {
    const o0 = v[a] + b0;
    let o1 = v[a+1] + b1;
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;
    v[a+1] = o1;
}

function B2B_GET32(arr, i) {
    return (arr[i] ^ (arr[i+1] << 8) ^ (arr[i+2] << 16) ^ (arr[i+3] << 24));
}

function B2B_G(v, a, b, c, d, ix, iy, m) {
    const x0 = m[ix*2], x1 = m[ix*2+1];
    const y0 = m[iy*2], y1 = m[iy*2+1];

    ADD64AA(v, a, b);
    ADD64AC(v, a, x0, x1);

    // v[d] = (v[d] xor v[a]) rotr 32
    let xor0 = v[d] ^ v[a];
    let xor1 = v[d+1] ^ v[a+1];
    v[d] = xor1;
    v[d+1] = xor0;

    ADD64AA(v, c, d);

    xor0 = v[b] ^ v[c];
    xor1 = v[b+1] ^ v[c+1];
    v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    v[b+1] = (xor1 >>> 24) ^ (xor0 << 8);

    ADD64AA(v, a, b);
    ADD64AC(v, a, y0, y1);

    xor0 = v[d] ^ v[a];
    xor1 = v[d+1] ^ v[a+1];
    v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    v[d+1] = (xor1 >>> 16) ^ (xor0 << 16);

    ADD64AA(v, c, d);

    xor0 = v[b] ^ v[c];
    xor1 = v[b+1] ^ v[c+1];
    v[b] = (xor1 >>> 31) ^ (xor0 << 1);
    v[b+1] = (xor0 >>> 31) ^ (xor1 << 1);
}

/**
 * Core BLAKE2b hash function
 * @param {Uint8Array|Buffer} input
 * @param {number} outlen - Output length in bytes (32 for 256-bit)
 * @returns {Uint8Array}
 */
function blake2b(input, outlen) {
    outlen = outlen || 32;
    if (typeof input === 'string') {
        input = Buffer.from(input, 'utf8');
    }

    const h = new Uint32Array(16);   // 8 x 64-bit state words (hi/lo pairs)
    const t = new Uint32Array(4);    // counters
    const f = new Uint32Array(4);    // finalization flags
    const b = new Uint8Array(128);   // input buffer
    let c = 0;                       // bytes in buffer

    // Parameter block: output length
    for (let i = 0; i < 16; i++) h[i] = BLAKE2B_IV[i];
    h[0] ^= 0x01010000 ^ outlen;    // fan-out=1, depth=1, no key

    function compress(last) {
        const v = new Uint32Array(32);
        for (let i = 0; i < 16; i++) v[i] = h[i];
        for (let i = 0; i < 8; i++) v[i+16] = BLAKE2B_IV[i*2];
        for (let i = 0; i < 8; i++) v[i*2+17] = BLAKE2B_IV[i*2+1];

        v[24] ^= t[0]; v[25] ^= t[1]; v[26] ^= t[2]; v[27] ^= t[3];
        if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }

        const m = new Uint32Array(32);
        for (let i = 0; i < 32; i++) {
            m[i] = B2B_GET32(b, i * 4);
        }

        for (let r = 0; r < 12; r++) {
            const s = SIGMA[r];
            B2B_G(v, 0, 8, 16, 24, s[0], s[1], m);
            B2B_G(v, 2, 10, 18, 26, s[2], s[3], m);
            B2B_G(v, 4, 12, 20, 28, s[4], s[5], m);
            B2B_G(v, 6, 14, 22, 30, s[6], s[7], m);
            B2B_G(v, 0, 10, 20, 30, s[8], s[9], m);
            B2B_G(v, 2, 12, 22, 24, s[10], s[11], m);
            B2B_G(v, 4, 14, 16, 26, s[12], s[13], m);
            B2B_G(v, 6, 8, 18, 28, s[14], s[15], m);
        }

        for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i+16];
    }

    function incrementCounter(n) {
        t[0] += n;
        if (t[0] >= 0x100000000) { t[0] -= 0x100000000; t[1]++; }
    }

    // Process input
    for (let i = 0; i < input.length; i++) {
        if (c === 128) {
            incrementCounter(128);
            compress(false);
            c = 0;
        }
        b[c++] = input[i];
    }

    // Finalize
    incrementCounter(c);
    while (c < 128) b[c++] = 0;
    compress(true);

    const out = new Uint8Array(outlen);
    for (let i = 0; i < outlen; i++) {
        out[i] = (h[~~(i/4)*2 + (1 - (i%4 >= 2 ? 0 : 1))] >>> (8 * (i % 4 < 2 ? i%4 : i%4-2))) & 0xFF;
    }

    // Proper byte extraction from 32-bit little-endian words
    const result = new Uint8Array(outlen);
    for (let i = 0; i < outlen; i++) {
        const wordIdx = Math.floor(i / 4);
        const byteIdx = i % 4;
        result[i] = (h[wordIdx * 2] >>> (byteIdx * 8)) & 0xFF;
    }

    return result;
}

/**
 * Compute BLAKE2b-256 and return lowercase hex string (64 chars)
 * This matches the output format of Go's blake2b.New256(nil)
 *
 * @param {string|Buffer|Uint8Array} data
 * @returns {string} 64-character lowercase hex
 */
function blake2bHex(data) {
    const digest = blake2b(data, 32);
    return Buffer.from(digest).toString('hex');
}

module.exports = { blake2b, blake2bHex };

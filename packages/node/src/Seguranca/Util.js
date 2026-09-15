'use strict';

const crypto = require('crypto');

/** Inteiro aleatório em [min, max], inclusivo (equivalente ao random_int do PHP). */
function randomInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

/** N bytes aleatórios (equivalente ao random_bytes do PHP). */
function randomBytes(n) {
  return crypto.randomBytes(n);
}

/** Converte string (binária/utf8) ou Buffer para Buffer. */
function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(value, 'binary');
}

/** Conta quantos bits diferem entre dois buffers/strings de mesmo tamanho. */
function bitsDiferentes(a, b) {
  const A = toBuffer(a);
  const B = toBuffer(b);
  const len = Math.min(A.length, B.length);
  let diff = 0;
  for (let i = 0; i < len; i++) {
    diff += contarBits1(A[i] ^ B[i]);
  }
  return diff;
}

/** Popcount de um byte (0-255). */
function contarBits1(byte) {
  let x = byte & 0xff;
  let count = 0;
  while (x) {
    count += x & 1;
    x >>= 1;
  }
  return count;
}

/** Popcount total de um buffer. */
function contarBitsBuffer(buf) {
  let total = 0;
  for (let i = 0; i < buf.length; i++) {
    total += contarBits1(buf[i]);
  }
  return total;
}

/** Fisher-Yates: embaralha uma cópia do array. */
function shuffle(array) {
  const out = array.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(0, i);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** Chave aleatória de um objeto (equivalente ao array_rand do PHP). */
function arrayRandKey(obj) {
  const keys = Object.keys(obj);
  return keys[randomInt(0, keys.length - 1)];
}

module.exports = {
  randomInt,
  randomBytes,
  toBuffer,
  bitsDiferentes,
  contarBits1,
  contarBitsBuffer,
  shuffle,
  arrayRandKey,
};

import crypto from 'node:crypto';

/** Inteiro aleatório em [min, max], inclusivo (equivalente ao random_int do PHP). */
export function randomInt(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min + 1));
}

/** N bytes aleatórios (equivalente ao random_bytes do PHP). */
export function randomBytes(n: number): Buffer {
  return crypto.randomBytes(n);
}

/** Converte string (binária/utf8) ou Buffer para Buffer. */
export function toBuffer(value: Buffer | string): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(value, 'binary');
}

/** Conta quantos bits diferem entre dois buffers/strings de mesmo tamanho. */
export function bitsDiferentes(a: Buffer | string, b: Buffer | string): number {
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
export function contarBits1(byte: number): number {
  let x = byte & 0xff;
  let count = 0;
  while (x) {
    count += x & 1;
    x >>= 1;
  }
  return count;
}

/** Popcount total de um buffer. */
export function contarBitsBuffer(buf: Buffer): number {
  let total = 0;
  for (let i = 0; i < buf.length; i++) {
    total += contarBits1(buf[i]);
  }
  return total;
}

/** Fisher-Yates: embaralha uma cópia do array. */
export function shuffle<T>(array: T[]): T[] {
  const out = array.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(0, i);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** Chave aleatória de um objeto (equivalente ao array_rand do PHP). */
export function arrayRandKey<T extends object>(obj: T): keyof T {
  const keys = Object.keys(obj) as (keyof T)[];
  return keys[randomInt(0, keys.length - 1)];
}

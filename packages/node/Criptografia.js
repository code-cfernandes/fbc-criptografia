'use strict';

/**
 * Cifra caseira educacional — porte de Criptografia.php.
 *
 * Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
 *
 * Ver Criptografia.php para os comentários completos sobre o design
 * (difusão tipo butterfly, distâncias Fibonacci->primo, rotação via Pi).
 * Este arquivo replica a lógica byte a byte, sem "melhorias" - qualquer
 * mudança de comportamento aqui quebraria compatibilidade com tokens
 * gerados pela versão PHP.
 */

const crypto = require('crypto');

const TAM_BLOCO = 32;

// Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
const DISTANCIAS_DIFUSAO = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41]; // dobrado pra combater ataque integral

const DIGITOS_PI =
  '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

function rotEsquerda8(byte, n) {
  n &= 7;
  if (n === 0) return byte & 0xff;
  return ((byte << n) | (byte >>> (8 - n))) & 0xff;
}

function rotEsquerda32(val, n) {
  n &= 31;
  val = val >>> 0;
  if (n === 0) return val >>> 0;
  return ((val << n) | (val >>> (32 - n))) >>> 0;
}

function rotacaoDoRound(roundIdx) {
  const d = parseInt(DIGITOS_PI[roundIdx % DIGITOS_PI.length], 10);
  return (d % 7) + 1;
}

/** Um passo da recorrência tipo-Fibonacci pra uma posição do bloco. */
function passo(a, b, keyBuf, propositoBuf, posFib, roundIdx) {
  const n = rotacaoDoRound(roundIdx);

  let soma = (a + b) & 0xff;
  soma = rotEsquerda8(soma, n);
  soma ^= propositoBuf[posFib % propositoBuf.length];
  // A chave participa de CADA rodada, não só do estado inicial (ver
  // comentário equivalente em Criptografia.php sobre keystream(key,iv) ==
  // keystream(key^D, iv^D16) sem isso).
  soma ^= keyBuf[(posFib + roundIdx) % keyBuf.length];
  soma = (soma * 131) & 0xff;

  return [b, soma]; // novo a = b antigo; novo b = soma
}

/** Gera $tamanho bytes de keystream a partir de KEY + IV + propósito. */
function gerarKeystream(keyBuf, ivBuf, proposito, tamanho) {
  const bloco = TAM_BLOCO;
  const ivLen = ivBuf.length;
  const keyLen = keyBuf.length;
  const propositoBuf = Buffer.from(proposito, 'utf8');

  let a = new Array(bloco);
  let b = new Array(bloco);
  for (let pos = 0; pos < bloco; pos++) {
    a[pos] = keyBuf[pos % keyLen] ^ ivBuf[pos % ivLen];
    b[pos] = keyBuf[(pos + 1) % keyLen] ^ ivBuf[(pos + 1) % ivLen];
  }

  const partes = [];
  let totalGerado = 0;
  let roundIdx = 0;
  let posFibBase = 0;

  while (totalGerado < tamanho) {
    for (const dist of DISTANCIAS_DIFUSAO) {
      const novoB = new Array(bloco);
      for (let pos = 0; pos < bloco; pos++) {
        const [novoA, novoBb] = passo(a[pos], b[pos], keyBuf, propositoBuf, posFibBase + pos, roundIdx);
        a[pos] = novoA;
        novoB[pos] = novoBb;
      }

      // Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR
      // (ver comentário equivalente em Criptografia.php sobre por que isso
      // é essencial - combinação simétrica colapsa metades do bloco).
      const misturado = new Array(bloco);
      for (let pos = 0; pos < bloco; pos++) {
        const vizinho = novoB[(pos + dist) % bloco];
        misturado[pos] = rotEsquerda8(novoB[pos], 1) ^ vizinho;
      }
      b = misturado;
      roundIdx++;
    }

    posFibBase += bloco;
    partes.push(Buffer.from(b));
    totalGerado += bloco;
  }

  return Buffer.concat(partes).subarray(0, tamanho);
}

function xorBytes(dadosBuf, keystreamBuf) {
  const out = Buffer.alloc(dadosBuf.length);
  for (let i = 0; i < dadosBuf.length; i++) {
    out[i] = dadosBuf[i] ^ keystreamBuf[i];
  }
  return out;
}

/** "MAC" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes. */
function checksum(dadosBuf, keyBuf) {
  const saida = Buffer.alloc(32);

  for (let rodada = 0; rodada < 8; rodada++) {
    let acumulador = (0x811c9dc5 ^ (rodada * 0x01000193)) >>> 0;
    const keyLen = keyBuf.length;
    const len = dadosBuf.length;

    for (let i = 0; i < len; i++) {
      const byte = dadosBuf[i] ^ keyBuf[(i + rodada) % keyLen];
      acumulador = (acumulador ^ byte) >>> 0;
      // multiplicação 32 bits sem estourar precisão de inteiro do JS
      acumulador = Number((BigInt(acumulador) * 16777619n) & 0xffffffffn);
      acumulador = rotEsquerda32(acumulador, (i % 13) + 1);
    }

    // Finalização: sem isso, o último byte processado só passa por 1
    // multiply+rotate antes de virar saída, e sofre avalanche fraca
    // (medido ~25-30% em vez de ~50% nos últimos bytes do bloco de dados).
    for (let k = 0; k < 3; k++) {
      acumulador = (acumulador ^ (acumulador >>> 16)) >>> 0;
      acumulador = Number((BigInt(acumulador) * 16777619n) & 0xffffffffn);
      acumulador = rotEsquerda32(acumulador, 13);
    }

    saida[rodada * 4 + 0] = (acumulador >>> 24) & 0xff;
    saida[rodada * 4 + 1] = (acumulador >>> 16) & 0xff;
    saida[rodada * 4 + 2] = (acumulador >>> 8) & 0xff;
    saida[rodada * 4 + 3] = acumulador & 0xff;
  }

  return saida;
}

function base64urlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  if (str !== '' && !/^[A-Za-z0-9_-]+$/.test(str)) {
    throw new Error('Token contém caracteres inválidos.');
  }

  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  const mod = s.length % 4;
  if (mod === 1) {
    throw new Error('Comprimento de token inválido.');
  }
  if (mod) {
    s += '='.repeat(4 - mod);
  }

  const decoded = Buffer.from(s, 'base64');

  // Canonicidade: reencoda e compara - pega tanto caracteres que o Buffer
  // ignoraria silenciosamente quanto bits não-canônicos no último grupo.
  if (base64urlEncode(decoded) !== str) {
    throw new Error('Token não está em forma canônica.');
  }

  return decoded;
}

function getKey() {
  const key = process.env.FBC_KEY;
  if (!key || Buffer.byteLength(key, 'utf8') !== 32) {
    throw new Error('Chave deve ter 32 bytes.');
  }
  return Buffer.from(key, 'utf8');
}

function encrypt(text) {
  const key = getKey();
  const iv = crypto.randomBytes(16);
  const textBuf = Buffer.from(text, 'utf8');

  const encKeystream = gerarKeystream(key, iv, 'enc', textBuf.length);
  const ciphertext = xorBytes(textBuf, encKeystream);

  const macKey = gerarKeystream(key, iv, 'mac', TAM_BLOCO);
  const integridade = checksum(Buffer.concat([iv, ciphertext]), macKey);

  return 'FBC' + base64urlEncode(Buffer.concat([integridade, ciphertext, iv]));
}

function decrypt(text) {
  if (text.slice(0, 3) !== 'FBC') {
    throw new Error('Invalid text. Text must start with FBC.');
  }

  const key = getKey();
  const decoded = base64urlDecode(text.slice(3));

  const integridadeRecebida = decoded.subarray(0, TAM_BLOCO);
  const iv = decoded.subarray(decoded.length - 16);
  const ciphertext = decoded.subarray(TAM_BLOCO, decoded.length - 16);

  const macKey = gerarKeystream(key, iv, 'mac', TAM_BLOCO);
  const integridadeEsperada = checksum(Buffer.concat([iv, ciphertext]), macKey);

  if (
    integridadeRecebida.length !== integridadeEsperada.length ||
    !crypto.timingSafeEqual(integridadeEsperada, integridadeRecebida)
  ) {
    throw new Error('Token adulterado ou chave incorreta.');
  }

  const encKeystream = gerarKeystream(key, iv, 'enc', ciphertext.length);
  return xorBytes(ciphertext, encKeystream).toString('utf8');
}

module.exports = {
  encrypt,
  decrypt,
  base64urlEncode,
  base64urlDecode,
  // exportados só pra permitir os mesmos testes de baixo nível da suíte PHP
  _internal: { gerarKeystream, checksum, rotEsquerda8, rotEsquerda32 },
};
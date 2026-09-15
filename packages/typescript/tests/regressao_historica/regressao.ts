/**
 * Harness de regressão histórica.
 *
 * Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
 * bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
 * (vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
 * PRECISA resistir (vulneravel=false).
 */

import crypto from 'node:crypto';

import { _internal, base64urlDecode, base64urlEncode } from '../../src/Core/Criptografia.ts';
import { CriptografiaAlvo } from '../../src/Seguranca/CriptografiaAlvo.ts';

import { AtaqueCorrelacaoMesmoPlaintext } from '../../src/Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.ts';
import { AtaqueFoldEstrutural } from '../../src/Seguranca/Ataques/AtaqueFoldEstrutural.ts';
import { AtaqueAvalancheChecksum } from '../../src/Seguranca/Ataques/AtaqueAvalancheChecksum.ts';
import { AtaqueIntegral } from '../../src/Seguranca/Ataques/AtaqueIntegral.ts';
import { AtaqueSeparacaoChaveIV } from '../../src/Seguranca/Ataques/AtaqueSeparacaoChaveIV.ts';
import { AtaqueCanonicalizacaoToken } from '../../src/Seguranca/Ataques/AtaqueCanonicalizacaoToken.ts';

const TAM_BLOCO = 32;
const DIGITOS_PI =
  '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

function rotEsquerda8(byte: number, n: number): number {
  n &= 7;
  if (n === 0) return byte & 0xff;
  return ((byte << n) | (byte >>> (8 - n))) & 0xff;
}

function rotacaoDoRound(roundIdx: number): number {
  const d = parseInt(DIGITOS_PI[roundIdx % DIGITOS_PI.length], 10);
  return (d % 7) + 1;
}

// passo com mutações: bug 5 remove a reinserção da chave em cada rodada.
function passoComBug(
  bug: number,
  a: number,
  b: number,
  keyBuf: Buffer,
  propositoBuf: Buffer,
  posFib: number,
  roundIdx: number,
): [number, number] {
  const n = rotacaoDoRound(roundIdx);
  let soma = (a + b) & 0xff;
  soma = rotEsquerda8(soma, n);
  soma ^= propositoBuf[posFib % propositoBuf.length];
  if (bug !== 5) {
    soma ^= keyBuf[(posFib + roundIdx) % keyBuf.length];
  }
  soma = (soma * 131) & 0xff;
  return [b, soma];
}

// gerarKeystream com mutações: bugs 1, 2, 4, 5.
function gerarKeystreamComBug(
  bug: number,
  keyBuf: Buffer,
  ivBuf: Buffer,
  proposito: string,
  tamanho: number,
): Buffer {
  if (bug === 1) {
    // bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
    return _internal.gerarKeystream(keyBuf, Buffer.alloc(ivBuf.length), proposito, tamanho);
  }

  const bloco = TAM_BLOCO;
  // bug 2: o colapso de metades só acontece quando a distância é exatamente
  // metade do bloco (16) — reproduzimos a condição histórica.
  const distancias =
    bug === 4
      ? [3]
      : bug === 2
        ? [3, 5, 11, 19, 41, 16]
        : [3, 5, 11, 19, 41, 3, 5, 11, 19, 41];
  const ivLen = ivBuf.length;
  const keyLen = keyBuf.length;
  const propositoBuf = Buffer.from(proposito, 'utf8');

  const a: number[] = new Array<number>(bloco);
  let b: number[] = new Array<number>(bloco);
  for (let pos = 0; pos < bloco; pos++) {
    a[pos] = keyBuf[pos % keyLen] ^ ivBuf[pos % ivLen];
    b[pos] = keyBuf[(pos + 1) % keyLen] ^ ivBuf[(pos + 1) % ivLen];
  }

  const partes: Buffer[] = [];
  let totalGerado = 0;
  let roundIdx = 0;
  let posFibBase = 0;

  while (totalGerado < tamanho) {
    for (const dist of distancias) {
      const novoB: number[] = new Array<number>(bloco);
      for (let pos = 0; pos < bloco; pos++) {
        const [novoA, novoBb] = passoComBug(
          bug,
          a[pos],
          b[pos],
          keyBuf,
          propositoBuf,
          posFibBase + pos,
          roundIdx,
        );
        a[pos] = novoA;
        novoB[pos] = novoBb;
      }
      const misturado: number[] = new Array<number>(bloco);
      for (let pos = 0; pos < bloco; pos++) {
        const vizinho = novoB[(pos + dist) % bloco];
        if (bug === 2) {
          // bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
          misturado[pos] = rotEsquerda8(novoB[pos] ^ vizinho, 1);
        } else {
          misturado[pos] = rotEsquerda8(novoB[pos], 1) ^ vizinho;
        }
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

// checksum com mutação: bug 3 remove a finalização.
function checksumComBug(bug: number, dadosBuf: Buffer, keyBuf: Buffer): Buffer {
  const saida = Buffer.alloc(32);
  for (let rodada = 0; rodada < 8; rodada++) {
    let acumulador = (0x811c9dc5 ^ (rodada * 0x01000193)) >>> 0;
    const keyLen = keyBuf.length;
    for (let i = 0; i < dadosBuf.length; i++) {
      const byte = dadosBuf[i] ^ keyBuf[(i + rodada) % keyLen];
      acumulador = (acumulador ^ byte) >>> 0;
      acumulador = Number((BigInt(acumulador) * 16777619n) & 0xffffffffn);
      acumulador = _internal.rotEsquerda32(acumulador, (i % 13) + 1);
    }
    if (bug !== 3) {
      for (let k = 0; k < 3; k++) {
        acumulador = (acumulador ^ (acumulador >>> 16)) >>> 0;
        acumulador = Number((BigInt(acumulador) * 16777619n) & 0xffffffffn);
        acumulador = _internal.rotEsquerda32(acumulador, 13);
      }
    }
    saida[rodada * 4 + 0] = (acumulador >>> 24) & 0xff;
    saida[rodada * 4 + 1] = (acumulador >>> 16) & 0xff;
    saida[rodada * 4 + 2] = (acumulador >>> 8) & 0xff;
    saida[rodada * 4 + 3] = acumulador & 0xff;
  }
  return saida;
}

// base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo.
function base64urlDecodeComBug(bug: number, str: string): Buffer {
  if (bug !== 6) {
    return base64urlDecode(str);
  }
  let s = str.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
  const mod = s.length % 4;
  if (mod) s += '='.repeat(4 - mod);
  return Buffer.from(s, 'base64');
}

// Alvo que aponta para a cifra com o bug selecionado.
class SnapshotAlvo extends CriptografiaAlvo {
  private readonly bug: number;

  constructor(bug: number) {
    super();
    this.bug = bug;
  }

  override gerarKeystreamBruto(
    key: Buffer | string,
    iv: Buffer | string,
    proposito: string,
    tamanho: number,
  ): Buffer {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    const ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'binary');
    return gerarKeystreamComBug(this.bug, keyBuf, ivBuf, proposito, tamanho);
  }

  override checksumBruto(dados: Buffer | string, key: Buffer | string): Buffer {
    const dadosBuf = Buffer.isBuffer(dados) ? dados : Buffer.from(dados, 'binary');
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'binary');
    return checksumComBug(this.bug, dadosBuf, keyBuf);
  }

  override base64urlDecode(data: string): Buffer {
    return base64urlDecodeComBug(this.bug, data);
  }

  override encrypt(texto: string | Buffer): string {
    const key = Buffer.from(this.chaveDeTeste(), 'utf8');
    const iv = crypto.randomBytes(16);
    const textBuf = typeof texto === 'string' ? Buffer.from(texto, 'utf8') : Buffer.from(texto);
    const ks = this.gerarKeystreamBruto(key, iv, 'enc', textBuf.length);
    const ct = Buffer.alloc(textBuf.length);
    for (let i = 0; i < textBuf.length; i++) ct[i] = textBuf[i] ^ ks[i];
    const macKey = this.gerarKeystreamBruto(key, iv, 'mac', 32);
    const integridade = this.checksumBruto(Buffer.concat([iv, ct]), macKey);
    return 'FBC' + base64urlEncode(Buffer.concat([integridade, ct, iv]));
  }

  override decrypt(token: string): string {
    if (token.slice(0, 3) !== 'FBC') throw new Error('prefixo');
    const key = Buffer.from(this.chaveDeTeste(), 'utf8');
    const decoded = this.base64urlDecode(token.slice(3));
    const integ = decoded.subarray(0, 32);
    const iv = decoded.subarray(decoded.length - 16);
    const ct = decoded.subarray(32, decoded.length - 16);
    const macKey = this.gerarKeystreamBruto(key, iv, 'mac', 32);
    const esperado = this.checksumBruto(Buffer.concat([iv, ct]), macKey);
    if (!esperado.equals(integ)) throw new Error('MAC');
    const ks = this.gerarKeystreamBruto(key, iv, 'enc', ct.length);
    const out = Buffer.alloc(ct.length);
    for (let i = 0; i < ct.length; i++) out[i] = ct[i] ^ ks[i];
    return out.toString('utf8');
  }
}

const CASOS = [
  { bug: 1, descricao: 'keystream ignora o IV', ataque: new AtaqueCorrelacaoMesmoPlaintext() },
  { bug: 2, descricao: 'combinador simétrico (metades colapsam)', ataque: new AtaqueFoldEstrutural() },
  { bug: 3, descricao: 'checksum sem finalização', ataque: new AtaqueAvalancheChecksum() },
  { bug: 4, descricao: 'cinco rodadas de difusão', ataque: new AtaqueIntegral() },
  { bug: 5, descricao: 'chave só no estado inicial', ataque: new AtaqueSeparacaoChaveIV() },
  { bug: 6, descricao: 'base64 não estrito', ataque: new AtaqueCanonicalizacaoToken() },
];

console.log('='.repeat(72));
console.log('REGRESSÃO HISTÓRICA');
console.log('='.repeat(72));

let falhas = 0;
for (const caso of CASOS) {
  const snapshot = new SnapshotAlvo(caso.bug);
  const real = new CriptografiaAlvo();

  let rSnapshot;
  let rReal;
  try {
    rSnapshot = caso.ataque.executar(snapshot);
    rReal = caso.ataque.executar(real);
  } catch (e) {
    console.log(`  ❌ bug ${caso.bug} (${caso.descricao}): erro — ${(e as Error).message}`);
    falhas++;
    continue;
  }

  const detectou = rSnapshot.vulneravel === true;
  const resistiu = rReal.vulneravel === false;
  const ok = detectou && resistiu;
  if (!ok) falhas++;

  console.log(
    `  ${ok ? '✅' : '❌'} bug ${caso.bug} (${caso.descricao}): ` +
      `snapshot ${detectou ? 'detectado' : 'NÃO detectado'} | atual ${resistiu ? 'resistiu' : 'ACUSOU'}`,
  );
  if (!ok) {
    console.log(`       snapshot: ${rSnapshot.linhaResumo()}`);
    console.log(`       atual:    ${rReal.linhaResumo()}`);
  }
}

console.log('='.repeat(72));
if (falhas === 0) {
  console.log(`RESUMO: ${CASOS.length} bugs históricos detectados; código atual resiste a todos.`);
} else {
  console.log(`RESUMO: ${falhas} caso(s) falharam.`);
}
console.log('='.repeat(72));

process.exit(falhas === 0 ? 0 : 1);

// Runner de fuzzing cruzado: gera keystreams e checksums brutos a partir de
// fuzz/casos.txt para comparação com as demais implementações.
// uso: node bin/fuzz_cruzado.ts <entrada> <saida>

import { readFileSync, writeFileSync } from 'node:fs';

import { CriptografiaAlvo } from '../src/Seguranca/CriptografiaAlvo.ts';

const caminhoEntrada = process.argv[2];
const caminhoSaida = process.argv[3];

if (!caminhoEntrada || !caminhoSaida) {
  console.error('uso: node bin/fuzz_cruzado.ts <entrada> <saida>');
  process.exit(1);
}

const alvo = new CriptografiaAlvo();

const linhas = readFileSync(caminhoEntrada, 'utf8')
  .split('\n')
  .map((linha) => linha.trim())
  .filter((linha) => linha.length > 0);

const saida: string[] = [];

for (let indice = 0; indice < linhas.length; indice++) {
  const [chaveHex, ivHex, proposito, plaintextHex] = linhas[indice].split('|');

  const chave = Buffer.from(chaveHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const plaintext = Buffer.from(plaintextHex, 'hex');

  const ks = alvo.gerarKeystreamBruto(chave, iv, proposito, plaintext.length);
  const mac = alvo.checksumBruto(plaintext, chave);

  saida.push(`${indice}|${ks.toString('hex')}|${mac.toString('hex')}`);
}

writeFileSync(caminhoSaida, `${saida.join('\n')}\n`);

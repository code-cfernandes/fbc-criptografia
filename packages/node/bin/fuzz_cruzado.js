'use strict';

const fs = require('fs');
const CriptografiaAlvo = require('../src/Seguranca/CriptografiaAlvo.js');

const [, , entrada, saida] = process.argv;
if (!entrada || !saida) {
  process.stderr.write('Uso: node bin/fuzz_cruzado.js <entrada> <saida>\n');
  process.exit(1);
}

let conteudo;
try {
  conteudo = fs.readFileSync(entrada, 'utf8');
} catch (erro) {
  process.stderr.write(`Não foi possível ler: ${entrada}\n`);
  process.exit(1);
}

const linhas = conteudo
  .split('\n')
  .map((linha) => linha.trim())
  .filter((linha) => linha !== '');

const alvo = new CriptografiaAlvo();
const saidaBuf = [];

linhas.forEach((linha, indice) => {
  const partes = linha.split('|');
  if (partes.length < 4) {
    process.stderr.write(`Linha malformada no índice ${indice}: ${linha}\n`);
    process.exit(1);
  }

  const [chaveHex, ivHex, proposito, plaintextHex] = partes;

  const chave = Buffer.from(chaveHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const plaintext = plaintextHex === '' ? Buffer.alloc(0) : Buffer.from(plaintextHex, 'hex');

  const ks = alvo.gerarKeystreamBruto(chave, iv, proposito, plaintext.length);
  const mac = alvo.checksumBruto(plaintext, chave);

  saidaBuf.push(`${indice}|${ks.toString('hex')}|${mac.toString('hex')}`);
});

fs.writeFileSync(saida, saidaBuf.join('\n') + '\n');

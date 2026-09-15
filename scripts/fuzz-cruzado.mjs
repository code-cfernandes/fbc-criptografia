#!/usr/bin/env node
// Fuzzing cruzado entre as 10 linguagens.
//
// Gera N casos determinísticos (chave, iv, proposito, plaintext), roda o runner
// de cada linguagem e compara as saídas (keystream + checksum) linha a linha.
//
// uso:
//   pnpm fuzz              # 1000 casos
//   pnpm fuzz --casos 5000 # quantidade customizada

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const dirFuzz = join(raiz, 'fuzz');
mkdirSync(dirFuzz, { recursive: true });

const argCasos = process.argv.indexOf('--casos');
const totalCasos = argCasos === -1 ? 1000 : Number(process.argv[argCasos + 1]);

const ORDEM = ['php', 'node', 'typescript', 'python', 'bash', 'java', 'go', 'rust', 'dart', 'julia'];
const NOMES = {
  php: '@criptografia/php',
  node: '@criptografia/node',
  typescript: '@criptografia/typescript',
  python: '@criptografia/python',
  bash: '@criptografia/bash',
  java: '@criptografia/java',
  go: '@criptografia/go',
  rust: '@criptografia/rust',
  dart: '@criptografia/dart',
  julia: '@criptografia/julia',
};

// PRNG determinístico (mulberry32) para casos reprodutíveis.
function criarRng(semente) {
  let a = semente >>> 0;
  return function rng() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function gerarCaso(rng, tamanho) {
  const degenerada = rng() < 0.15;
  let chave;
  if (degenerada) {
    const tipo = Math.floor(rng() * 4);
    chave = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      chave[i] = tipo === 0 ? 0x00 : tipo === 1 ? 0xff : tipo === 2 ? (i % 2 ? 0xaa : 0x55) : i & 0xff;
    }
  } else {
    chave = Buffer.from(Array.from({ length: 32 }, () => Math.floor(rng() * 256)));
  }

  const ivDegenerado = rng() < 0.15;
  let iv;
  if (ivDegenerado) {
    const tipo = Math.floor(rng() * 3);
    iv = Buffer.alloc(16, tipo === 0 ? 0x00 : tipo === 1 ? 0xff : 0xaa);
  } else {
    iv = Buffer.from(Array.from({ length: 16 }, () => Math.floor(rng() * 256)));
  }

  const proposito = rng() < 0.5 ? 'enc' : 'mac';
  const plaintext = Buffer.from(Array.from({ length: tamanho }, () => Math.floor(rng() * 256)));
  if (tamanho > 0 && rng() < 0.25) {
    plaintext[Math.floor(rng() * tamanho)] = 0x00;
  }

  return `${hex(chave)}|${hex(iv)}|${proposito}|${hex(plaintext)}`;
}

function gerarCasos() {
  const rng = criarRng(0xfbc0de);
  const casos = [];
  const tamanhosFixos = [0, 1, 31, 32, 33, 63, 64, 65, 1000];
  for (const tam of tamanhosFixos) {
    for (let i = 0; i < 20; i++) casos.push(gerarCaso(rng, tam));
  }
  while (casos.length < totalCasos) {
    const tam = rng() < 0.6 ? Math.floor(rng() * 70) : Math.floor(rng() * 1200);
    casos.push(gerarCaso(rng, tam));
  }
  return casos.slice(0, Math.max(totalCasos, tamanhosFixos.length * 20));
}

const caminhoCasos = join(dirFuzz, 'casos.txt');
const casos = gerarCasos();
writeFileSync(caminhoCasos, casos.join('\n') + '\n');
console.log(`Gerados ${casos.length} casos em fuzz/casos.txt\n`);

const resultados = {};
for (const lang of ORDEM) {
  const saida = join(dirFuzz, `resultados_${lang}.txt`);
  const inicio = process.hrtime.bigint();
  const proc = spawnSync(
    'pnpm',
    ['--filter', NOMES[lang], 'run', 'fuzz', caminhoCasos, saida],
    { cwd: raiz, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 },
  );
  const ms = Number(process.hrtime.bigint() - inicio) / 1e6;
  if (proc.status !== 0) {
    console.log(`  ❌ ${lang.padEnd(11)} falhou (exit ${proc.status})`);
    console.log((proc.stdout ?? '') + (proc.stderr ?? ''));
    resultados[lang] = null;
    continue;
  }
  const linhas = readFileSync(saida, 'utf8').trim().split('\n');
  resultados[lang] = linhas;
  console.log(`  ✅ ${lang.padEnd(11)} ${linhas.length} resultados  ${(ms / 1000).toFixed(1)}s`);
}

console.log('\n' + '='.repeat(72));
console.log('FUZZING CRUZADO — comparação entre linguagens');
console.log('='.repeat(72));

const base = resultados[ORDEM[0]];
if (!base) {
  console.error('Linguagem de referência (php) falhou.');
  process.exit(1);
}

let divergencias = 0;
for (const lang of ORDEM.slice(1)) {
  const linhas = resultados[lang];
  if (!linhas) {
    divergencias++;
    continue;
  }
  if (linhas.length !== base.length) {
    console.log(`  ❌ ${lang}: ${linhas.length} linhas (esperado ${base.length})`);
    divergencias++;
    continue;
  }
  let primeiraDiv = -1;
  for (let i = 0; i < base.length; i++) {
    if (linhas[i] !== base[i]) {
      primeiraDiv = i;
      break;
    }
  }
  if (primeiraDiv === -1) {
    console.log(`  ✅ ${lang}: idêntico (${base.length} casos)`);
  } else {
    console.log(`  ❌ ${lang}: diverge no caso ${primeiraDiv}`);
    console.log(`       php : ${base[primeiraDiv]}`);
    console.log(`       ${lang.padEnd(4)}: ${linhas[primeiraDiv]}`);
    divergencias++;
  }
}

console.log('='.repeat(72));
if (divergencias === 0) {
  console.log(`RESUMO: ${casos.length} casos idênticos nas ${ORDEM.length} linguagens.`);
} else {
  console.log(`RESUMO: ${divergencias} linguagem(ns) divergente(s).`);
}
console.log('='.repeat(72));

process.exit(divergencias === 0 ? 0 : 1);

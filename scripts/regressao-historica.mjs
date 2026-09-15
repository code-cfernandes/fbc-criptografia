#!/usr/bin/env node
// Roda o harness de regressão histórica de cada linguagem e consolida.
//
// uso:
//   pnpm regressao
//   pnpm regressao --detalhado

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const detalhado = process.argv.includes('--detalhado') || process.argv.includes('-v');

const ORDEM = ['php', 'node', 'typescript', 'python', 'bash', 'java', 'go', 'rust', 'dart', 'julia'];

function listarPacotes() {
  const pacotes = [];
  for (const dir of readdirSync(join(raiz, 'packages'))) {
    const caminho = join(raiz, 'packages', dir, 'package.json');
    if (!existsSync(caminho)) continue;
    const pkg = JSON.parse(readFileSync(caminho, 'utf8'));
    if (!pkg.scripts || !pkg.scripts.regressao) continue;
    pacotes.push({ dir, nome: pkg.name });
  }
  pacotes.sort((a, b) => {
    const ia = ORDEM.indexOf(a.dir);
    const ib = ORDEM.indexOf(b.dir);
    return (ia === -1 ? ORDEM.length : ia) - (ib === -1 ? ORDEM.length : ib) ||
      a.dir.localeCompare(b.dir);
  });
  return pacotes;
}

const pacotes = listarPacotes();
console.log(`Executando regressão histórica em ${pacotes.length} linguagens...\n`);

const resultados = [];
for (const pacote of pacotes) {
  const inicio = process.hrtime.bigint();
  const proc = spawnSync('pnpm', ['--filter', pacote.nome, 'run', 'regressao'], {
    cwd: raiz,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const ms = Number(process.hrtime.bigint() - inicio) / 1e6;
  const saida = `${proc.stdout ?? ''}${proc.stderr ?? ''}`;
  const okLinhas = (saida.match(/✅ bug/g) || []).length;
  const falhas = (saida.match(/❌ bug/g) || []).length;
  const temResumo = /RESUMO:.*bugs históricos detectados/.test(saida);
  const ok = proc.status === 0 && temResumo && falhas === 0;

  resultados.push({ ...pacote, ms, ok, saida, okLinhas, falhas });

  if (detalhado) {
    console.log(`----- ${pacote.dir} -----`);
    console.log(saida.trimEnd());
    console.log();
  } else {
    console.log(
      `  ${ok ? '✅' : '❌'} ${pacote.dir.padEnd(11)} ${okLinhas}/6 bugs detectados  ${(ms / 1000).toFixed(1)}s`,
    );
  }
}

const largura = Math.max(9, ...resultados.map((r) => r.dir.length));
const totalMs = resultados.reduce((soma, r) => soma + r.ms, 0);
const tudoOk = resultados.every((r) => r.ok);

console.log();
console.log('='.repeat(72));
console.log('REGRESSÃO HISTÓRICA — CONSOLIDADO');
console.log('='.repeat(72));
console.log(`${'Linguagem'.padEnd(largura)}  Bugs  Tempo    Status`);
console.log('-'.repeat(72));
for (const r of resultados) {
  console.log(
    `${r.dir.padEnd(largura)}  ${String(r.okLinhas).padStart(4)}  ${((r.ms / 1000).toFixed(1) + 's').padStart(7)}  ${r.ok ? '✅ ok' : '❌ falhou'}`,
  );
}
console.log('-'.repeat(72));
console.log(
  `${'TOTAL'.padEnd(largura)}  ${String(resultados.reduce((s, r) => s + r.okLinhas, 0)).padStart(4)}  ${((totalMs / 1000).toFixed(1) + 's').padStart(7)}  ${tudoOk ? '✅ ok' : '❌ falhou'}`,
);
console.log('='.repeat(72));

const comFalha = resultados.filter((r) => !r.ok);
if (comFalha.length > 0) {
  console.log(`\nCom falha: ${comFalha.map((r) => r.dir).join(', ')}`);
  for (const r of comFalha) {
    console.log(`\n----- ${r.dir} -----\n${r.saida.trimEnd().split('\n').slice(-12).join('\n')}`);
  }
}

process.exit(tudoOk ? 0 : 1);

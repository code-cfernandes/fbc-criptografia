#!/usr/bin/env node
// Roda TODAS as frentes de teste e imprime um relatório consolidado:
//   1. suíte de ataques (por linguagem)
//   2. fuzzing cruzado entre as linguagens
//   3. regressão histórica
//
// uso:
//   pnpm test                # relatório consolidado
//   pnpm test --detalhado    # inclui a saída completa de cada frente

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const detalhado = process.argv.includes('--detalhado') || process.argv.includes('-v');

const ORDEM = ['node', 'typescript', 'java', 'go', 'rust', 'dart', 'julia', 'php', 'python', 'bash'];

function segundos(ms) {
  return `${(ms / 1000).toFixed(1)}s`;
}

function rodar(comando, argumentos) {
  const inicio = process.hrtime.bigint();
  const proc = spawnSync(comando, argumentos, {
    cwd: raiz,
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
  });
  return {
    status: proc.status,
    saida: `${proc.stdout ?? ''}${proc.stderr ?? ''}`,
    ms: Number(process.hrtime.bigint() - inicio) / 1e6,
  };
}

function listarPacotes() {
  const pacotes = [];
  for (const dir of readdirSync(join(raiz, 'packages'))) {
    const caminho = join(raiz, 'packages', dir, 'package.json');
    if (!existsSync(caminho)) continue;
    const pkg = JSON.parse(readFileSync(caminho, 'utf8'));
    if (!pkg.scripts || !pkg.scripts.test) continue;
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

function interpretarAtaques(saida) {
  const ok = saida.match(/RESUMO:\s*nenhuma vulnerabilidade encontrada em (\d+) ataque/);
  if (ok) return { ataques: Number(ok[1]), vulnerabilidades: 0, temResumo: true };
  const ruim = saida.match(/RESUMO:\s*(\d+) vulnerabilidade\(s\) encontrada\(s\) de (\d+) ataque/);
  if (ruim) return { ataques: Number(ruim[2]), vulnerabilidades: Number(ruim[1]), temResumo: true };
  const linhas = (saida.match(/^\s*\[(?:✅|❌|PULADO|DEMONSTRAÇÃO)/gm) || []).length;
  const vulnerabilidades = (saida.match(/❌ VULNERÁVEL/g) || []).length;
  return { ataques: linhas, vulnerabilidades, temResumo: false };
}

const versao = JSON.parse(readFileSync(join(raiz, 'package.json'), 'utf8')).version;
const pacotes = listarPacotes();

console.log(`Executando todas as frentes (versão ${versao})...\n`);
console.log('1/3 — suíte de ataques');

const ataques = [];
for (const pacote of pacotes) {
  const { status, saida, ms } = rodar('pnpm', ['--filter', pacote.nome, 'test']);
  const info = interpretarAtaques(saida);
  const ok = status === 0 && info.temResumo && info.vulnerabilidades === 0;
  ataques.push({ ...pacote, ms, ok, saida, ...info });
  if (detalhado) {
    console.log(`----- ${pacote.dir} -----\n${saida.trimEnd()}\n`);
  } else {
    console.log(
      `  ${ok ? '✅' : '❌'} ${pacote.dir.padEnd(11)} ${String(info.ataques).padStart(3)} ataque(s)  ${segundos(ms).padStart(7)}`,
    );
  }
}

console.log('\n2/3 — fuzzing cruzado');
const fuzz = rodar('node', ['scripts/fuzz-cruzado.mjs']);
const fuzzCasos = fuzz.saida.match(/RESUMO:\s*(\d+) casos idênticos/);
const fuzzOk = fuzz.status === 0 && fuzzCasos !== null;
if (detalhado) console.log(fuzz.saida.trimEnd());
console.log(`  ${fuzzOk ? '✅' : '❌'} fuzz ${fuzzCasos ? `${fuzzCasos[1]} casos idênticos` : 'falhou'}  ${segundos(fuzz.ms)}`);

console.log('\n3/3 — regressão histórica');
const regressao = rodar('node', ['scripts/regressao-historica.mjs']);
const regTotal = regressao.saida.match(/TOTAL\s+(\d+)\s+\S+\s+(✅ ok|❌ falhou)/);
const regressaoOk = regressao.status === 0 && regTotal !== null && regTotal[2] === '✅ ok';
if (detalhado) console.log(regressao.saida.trimEnd());
console.log(
  `  ${regressaoOk ? '✅' : '❌'} regressão ${regTotal ? `${regTotal[1]} detecções` : 'falhou'}  ${segundos(regressao.ms)}`,
);

// ----- relatório consolidado -----
const largura = Math.max(9, ...ataques.map((a) => a.dir.length));
const totalAtaques = ataques.reduce((s, a) => s + a.ataques, 0);
const totalVulnerabilidades = ataques.reduce((s, a) => s + a.vulnerabilidades, 0);
const totalMsAtaques = ataques.reduce((s, a) => s + a.ms, 0);
const ataquesOk = ataques.every((a) => a.ok);
const tudoOk = ataquesOk && fuzzOk && regressaoOk;

const sep = '='.repeat(74);
const div = '-'.repeat(74);

console.log(`\n${sep}`);
console.log(`RELATÓRIO CONSOLIDADO — versão ${versao}`);
console.log(sep);

console.log('SUÍTE DE ATAQUES');
console.log(`${'Linguagem'.padEnd(largura)} ${'Ataques'.padStart(7)} ${'Vulnerab.'.padStart(9)} ${'Tempo'.padStart(8)}  Status`);
console.log(div);
for (const a of ataques) {
  console.log(
    `${a.dir.padEnd(largura)} ${String(a.ataques).padStart(7)} ${String(a.vulnerabilidades).padStart(9)} ${segundos(a.ms).padStart(8)}  ${a.ok ? '✅ ok' : '❌ falhou'}`,
  );
}
console.log(div);
console.log(
  `${'TOTAL'.padEnd(largura)} ${String(totalAtaques).padStart(7)} ${String(totalVulnerabilidades).padStart(9)} ${segundos(totalMsAtaques).padStart(8)}  ${ataquesOk ? '✅ ok' : '❌ falhou'}`,
);

console.log(`\nFUZZING CRUZADO`);
console.log(
  `  ${fuzzOk ? '✅' : '❌'} ${fuzzCasos ? `${fuzzCasos[1]} casos idênticos nas ${pacotes.length} linguagens` : 'divergências encontradas'}  (${segundos(fuzz.ms)})`,
);

console.log(`\nREGRESSÃO HISTÓRICA`);
console.log(
  `  ${regressaoOk ? '✅' : '❌'} ${regTotal ? `${regTotal[1]} detecções (6 bugs × ${pacotes.length} linguagens + NUL no bash)` : 'falhas encontradas'}  (${segundos(regressao.ms)})`,
);

console.log(`\n${sep}`);
console.log(
  tudoOk
    ? `RESUMO GERAL: tudo ok — 3 frentes verdes (ataques ${totalAtaques}, fuzz ${fuzzCasos ? fuzzCasos[1] : '?'} casos, regressão ${regTotal ? regTotal[1] : '?'} detecções).`
    : `RESUMO GERAL: há falhas (ataques ${ataquesOk ? 'ok' : 'falhou'}, fuzz ${fuzzOk ? 'ok' : 'falhou'}, regressão ${regressaoOk ? 'ok' : 'falhou'}).`,
);
console.log(sep);

if (!tudoOk) {
  for (const a of ataques.filter((x) => !x.ok)) {
    console.log(`\n----- ${a.dir} (últimas linhas) -----\n${a.saida.trimEnd().split('\n').slice(-8).join('\n')}`);
  }
  if (!fuzzOk) console.log(`\n----- fuzz (últimas linhas) -----\n${fuzz.saida.trimEnd().split('\n').slice(-12).join('\n')}`);
  if (!regressaoOk) console.log(`\n----- regressão (últimas linhas) -----\n${regressao.saida.trimEnd().split('\n').slice(-12).join('\n')}`);
}

process.exit(tudoOk ? 0 : 1);

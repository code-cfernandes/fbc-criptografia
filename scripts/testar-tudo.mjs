#!/usr/bin/env node
// Roda a suíte de todas as linguagens e imprime um relatório consolidado.
//
// uso:
//   pnpm test                # relatório consolidado
//   pnpm test --detalhado    # inclui a saída completa de cada linguagem

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const detalhado = process.argv.includes('--detalhado') || process.argv.includes('-v');

// Ordem de exibição (as demais entram em ordem alfabética no fim).
const ORDEM = ['php', 'node', 'typescript', 'python', 'java', 'go', 'rust', 'dart', 'julia', 'bash'];

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

function interpretar(saida) {
  const semVulnerabilidade = saida.match(/RESUMO:\s*nenhuma vulnerabilidade encontrada em (\d+) ataque/);
  if (semVulnerabilidade) {
    return { ataques: Number(semVulnerabilidade[1]), vulnerabilidades: 0, temResumo: true };
  }
  const comVulnerabilidade = saida.match(/RESUMO:\s*(\d+) vulnerabilidade\(s\) encontrada\(s\) de (\d+) ataque/);
  if (comVulnerabilidade) {
    return {
      ataques: Number(comVulnerabilidade[2]),
      vulnerabilidades: Number(comVulnerabilidade[1]),
      temResumo: true,
    };
  }
  const linhas = (saida.match(/^\s*\[(?:✅|❌|PULADO|DEMONSTRAÇÃO)/gm) || []).length;
  const vulnerabilidades = (saida.match(/❌ VULNERÁVEL/g) || []).length;
  return { ataques: linhas, vulnerabilidades, temResumo: false };
}

function segundos(ms) {
  return `${(ms / 1000).toFixed(1)}s`;
}

const pacotes = listarPacotes();
const versao = JSON.parse(readFileSync(join(raiz, 'package.json'), 'utf8')).version;

console.log(`Executando ${pacotes.length} linguagens (versão ${versao})...\n`);

const resultados = [];
for (const pacote of pacotes) {
  const inicio = process.hrtime.bigint();
  const proc = spawnSync('pnpm', ['--filter', pacote.nome, 'test'], {
    cwd: raiz,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  const ms = Number(process.hrtime.bigint() - inicio) / 1e6;
  const saida = `${proc.stdout ?? ''}${proc.stderr ?? ''}`;
  const info = interpretar(saida);
  const ok = proc.status === 0 && info.temResumo && info.vulnerabilidades === 0;

  resultados.push({ ...pacote, ms, ok, saida, ...info });

  if (detalhado) {
    console.log(`----- ${pacote.dir} -----`);
    console.log(saida.trimEnd());
    console.log();
  } else {
    const marca = ok ? '✅' : '❌';
    console.log(
      `  ${marca} ${pacote.dir.padEnd(11)} ${String(info.ataques).padStart(3)} ataque(s)  ${segundos(ms).padStart(7)}`,
    );
  }
}

const larguraLinguagem = Math.max(9, ...resultados.map((r) => r.dir.length));
const linhas = resultados.map((r) => ({
  linguagem: r.dir.padEnd(larguraLinguagem),
  ataques: String(r.ataques).padStart(7),
  vulnerabilidades: String(r.vulnerabilidades).padStart(14),
  tempo: segundos(r.ms).padStart(8),
  status: r.ok ? '✅ ok' : '❌ falhou',
}));

const totalAtaques = resultados.reduce((soma, r) => soma + r.ataques, 0);
const totalVulnerabilidades = resultados.reduce((soma, r) => soma + r.vulnerabilidades, 0);
const totalMs = resultados.reduce((soma, r) => soma + r.ms, 0);
const tudoOk = resultados.every((r) => r.ok);

const separador = '='.repeat(72);
const divisor = '-'.repeat(72);

console.log();
console.log(separador);
console.log(`RELATÓRIO CONSOLIDADO — ${resultados.length} linguagens, versão ${versao}`);
console.log(separador);
console.log(
  `${'Linguagem'.padEnd(larguraLinguagem)} ${'Ataques'.padStart(7)} ${'Vulnerabilidades'.padStart(14)} ${'Tempo'.padStart(8)}  Status`,
);
console.log(divisor);
for (const l of linhas) {
  console.log(`${l.linguagem} ${l.ataques} ${l.vulnerabilidades} ${l.tempo}  ${l.status}`);
}
console.log(divisor);
console.log(
  `${'TOTAL'.padEnd(larguraLinguagem)} ${String(totalAtaques).padStart(7)} ${String(totalVulnerabilidades).padStart(14)} ${segundos(totalMs).padStart(8)}  ${tudoOk ? '✅ ok' : '❌ falhou'}`,
);
console.log(separador);

const comFalha = resultados.filter((r) => !r.ok);
if (comFalha.length > 0) {
  console.log(`\nLinguagem(ns) com falha: ${comFalha.map((r) => r.dir).join(', ')}`);
  if (!detalhado) {
    console.log('Rode `pnpm test --detalhado` para ver a saída completa.');
    for (const r of comFalha) {
      const ultimas = r.saida.trimEnd().split('\n').slice(-8).join('\n');
      console.log(`\n----- ${r.dir} (últimas linhas) -----\n${ultimas}`);
    }
  }
}

process.exit(tudoOk ? 0 : 1);

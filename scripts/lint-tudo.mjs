#!/usr/bin/env node
// Roda toda a análise estática e imprime um relatório consolidado:
//   - linters por linguagem (ShellCheck, Clippy, PHPStan, dart analyze, JET/Aqua)
//   - auditoria de dependências (cargo-audit, composer audit, OSV-Scanner)
//   - SAST (Semgrep) e segredos (Gitleaks)
//
// uso:
//   pnpm lint                # relatório consolidado
//   pnpm lint --detalhado    # inclui a saída completa de cada checagem

import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const detalhado = process.argv.includes('--detalhado') || process.argv.includes('-v');

const EXCLUDES = [
  '--exclude',
  'vendor',
  '--exclude',
  'node_modules',
  '--exclude',
  'target',
  '--exclude',
  'build',
  '--exclude',
  '.dart_tool',
  '--exclude',
  'fuzz',
];

const CHECAGENS = [
  { nome: 'bash (ShellCheck)', tipo: 'pnpm', pacote: '@criptografia/bash', script: 'lint' },
  { nome: 'rust (Clippy)', tipo: 'pnpm', pacote: '@criptografia/rust', script: 'lint' },
  { nome: 'rust (cargo-audit)', tipo: 'pnpm', pacote: '@criptografia/rust', script: 'audit' },
  { nome: 'php (PHPStan)', tipo: 'pnpm', pacote: '@criptografia/php', script: 'analyse' },
  { nome: 'php (composer audit)', tipo: 'pnpm', pacote: '@criptografia/php', script: 'audit' },
  { nome: 'dart (dart analyze)', tipo: 'pnpm', pacote: '@criptografia/dart', script: 'lint' },
  { nome: 'julia (JET + Aqua)', tipo: 'pnpm', pacote: '@criptografia/julia', script: 'analyse' },
  { nome: 'SAST (Semgrep)', tipo: 'cmd', cmd: 'semgrep', args: ['scan', '--config', 'p/default', '--error', '--quiet', ...EXCLUDES, '.'] },
  { nome: 'segredos (Gitleaks)', tipo: 'cmd', cmd: 'gitleaks', args: ['detect', '--source', '.', '--no-banner', '--redact', '--config', '.gitleaks.toml'] },
  { nome: 'deps (OSV-Scanner)', tipo: 'cmd', cmd: 'osv-scanner', args: ['scan', 'source', '-r', '.'] },
];

function rodar(check) {
  const inicio = process.hrtime.bigint();
  const proc =
    check.tipo === 'pnpm'
      ? spawnSync('pnpm', ['--filter', check.pacote, 'run', check.script], {
          cwd: raiz,
          encoding: 'utf8',
          maxBuffer: 256 * 1024 * 1024,
        })
      : spawnSync(check.cmd, check.args, {
          cwd: raiz,
          encoding: 'utf8',
          maxBuffer: 256 * 1024 * 1024,
        });
  return {
    status: proc.status,
    saida: `${proc.stdout ?? ''}${proc.stderr ?? ''}`,
    ms: Number(process.hrtime.bigint() - inicio) / 1e6,
  };
}

console.log(`Rodando ${CHECAGENS.length} checagens de análise estática...\n`);

const resultados = [];
for (const check of CHECAGENS) {
  const r = rodar(check);
  const ok = r.status === 0;
  resultados.push({ ...check, ...r, ok });
  if (detalhado) {
    console.log(`----- ${check.nome} -----`);
    console.log(r.saida.trimEnd());
    console.log();
  } else {
    console.log(`  ${ok ? '✅' : '❌'} ${check.nome.padEnd(28)} ${(r.ms / 1000).toFixed(1)}s`);
  }
}

const largura = Math.max(20, ...resultados.map((r) => r.nome.length));
const totalMs = resultados.reduce((s, r) => s + r.ms, 0);
const tudoOk = resultados.every((r) => r.ok);

console.log();
console.log('='.repeat(74));
console.log('ANÁLISE ESTÁTICA — CONSOLIDADO');
console.log('='.repeat(74));
console.log(`${'Checagem'.padEnd(largura)}  Tempo    Status`);
console.log('-'.repeat(74));
for (const r of resultados) {
  console.log(`${r.nome.padEnd(largura)}  ${((r.ms / 1000).toFixed(1) + 's').padStart(7)}  ${r.ok ? '✅ ok' : '❌ falhou'}`);
}
console.log('-'.repeat(74));
console.log(`${'TOTAL'.padEnd(largura)}  ${((totalMs / 1000).toFixed(1) + 's').padStart(7)}  ${tudoOk ? '✅ ok' : '❌ falhou'}`);
console.log('='.repeat(74));

if (!tudoOk) {
  for (const r of resultados.filter((x) => !x.ok)) {
    console.log(`\n----- ${r.nome} (últimas linhas) -----`);
    console.log(r.saida.trimEnd().split('\n').slice(-15).join('\n'));
  }
}

process.exit(tudoOk ? 0 : 1);

#!/usr/bin/env node
// Gerencia a versão do monorepo (SemVer), mantendo todos os pacotes alinhados.
//
// uso:
//   node scripts/bump-versao.mjs major
//   node scripts/bump-versao.mjs minor
//   node scripts/bump-versao.mjs patch
//   node scripts/bump-versao.mjs 1.2.3      # define uma versão explícita

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..');
const tipo = process.argv[2];

if (!tipo) {
  console.error('uso: node scripts/bump-versao.mjs <major|minor|patch|x.y.z>');
  process.exit(1);
}

function proximaVersao(atual, tipo) {
  const [maior, menor, patch] = atual.split('.').map(Number);
  switch (tipo) {
    case 'major':
      return `${maior + 1}.0.0`;
    case 'minor':
      return `${maior}.${menor + 1}.0`;
    case 'patch':
      return `${maior}.${menor}.${patch + 1}`;
    default:
      if (/^\d+\.\d+\.\d+$/.test(tipo)) return tipo;
      throw new Error(`tipo/versão inválida: ${tipo}`);
  }
}

function listarArquivos() {
  const arquivos = [join(raiz, 'package.json')];
  for (const dir of readdirSync(join(raiz, 'packages'))) {
    const pkg = join(raiz, 'packages', dir, 'package.json');
    if (existsSync(pkg)) arquivos.push(pkg);
  }
  for (const extra of [
    'packages/php/composer.json',
    'packages/rust/Cargo.toml',
    'packages/dart/pubspec.yaml',
  ]) {
    const caminho = join(raiz, extra);
    if (existsSync(caminho)) arquivos.push(caminho);
  }
  return arquivos;
}

const raizPkg = JSON.parse(readFileSync(join(raiz, 'package.json'), 'utf8'));
const atual = raizPkg.version;
const nova = proximaVersao(atual, tipo);

for (const arquivo of listarArquivos()) {
  if (arquivo.endsWith('package.json') || arquivo.endsWith('composer.json')) {
    const json = JSON.parse(readFileSync(arquivo, 'utf8'));
    json.version = nova;
    const indent = arquivo.endsWith('composer.json') ? 4 : 2;
    writeFileSync(arquivo, JSON.stringify(json, null, indent) + '\n');
  } else if (arquivo.endsWith('Cargo.toml')) {
    const conteudo = readFileSync(arquivo, 'utf8');
    writeFileSync(arquivo, conteudo.replace(/^version = "[^"]+"/m, `version = "${nova}"`));
  } else if (arquivo.endsWith('pubspec.yaml')) {
    const conteudo = readFileSync(arquivo, 'utf8');
    writeFileSync(arquivo, conteudo.replace(/^version: .*$/m, `version: ${nova}`));
  }
  console.log(`  atualizado ${arquivo.replace(raiz + '/', '')} -> ${nova}`);
}

console.log(`\nversão: ${atual} -> ${nova}`);

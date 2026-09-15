// Ferramenta de desenvolvimento: roda um único ataque e imprime o resultado.
// uso: node bin/testar_um.ts <NomeDoAtaque>

import { CriptografiaAlvo } from '../src/Seguranca/CriptografiaAlvo.ts';
import type { AtaqueInterface } from '../src/Seguranca/AtaqueInterface.ts';

const nome = process.argv[2];
if (!nome) {
  console.error('uso: node bin/testar_um.ts <NomeDoAtaque>');
  process.exit(1);
}

const mod = (await import(`../src/Seguranca/Ataques/${nome}.ts`)) as Record<
  string,
  new () => AtaqueInterface
>;
const Ctor = mod[nome];
if (!Ctor) {
  console.error(`Ataque não encontrado: ${nome}`);
  process.exit(1);
}

const ataque = new Ctor();
const alvo = new CriptografiaAlvo();
console.log(ataque.executar(alvo).linhaResumo());

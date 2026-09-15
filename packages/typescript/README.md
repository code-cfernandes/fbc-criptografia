# Criptografia FBC — TypeScript

![TypeScript](https://img.shields.io/badge/TypeScript-7+-3178C6?logo=typescript&logoColor=white)

Implementação tipada da cifra caseira **FBC** em TypeScript, com a suíte de 40
ataques criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

Roda direto no Node (24+), sem build: o Node faz *type stripping* dos `.ts`. O
compilador `tsc` é usado apenas para checagem de tipos.

## Requisitos

- Node.js 24+ (type stripping nativo)
- `typescript` e `@types/node` (devDependencies, instaladas via `pnpm install`)

## Estrutura

```
src/
├── Core/Criptografia.ts           # encrypt / decrypt + _internal
└── Seguranca/
    ├── AlvoCriptografico.ts       # interface do alvo + CamposToken
    ├── AtaqueInterface.ts         # interface dos ataques
    ├── CriptografiaAlvo.ts        # liga a suíte à cifra (usa _internal)
    ├── ResultadoAtaque.ts         # classe + type Severidade
    ├── SkipAtaqueException.ts
    ├── SuiteDeAtaques.ts
    ├── Util.ts
    └── Ataques/*.ts               # 50 ataques
bin/
├── executar_testes.ts             # runner da suíte
└── testar_um.ts                   # roda um ataque isolado
```

ESM (`"type": "module"`), imports com extensão `.ts`, `strict` +
`verbatimModuleSyntax` + `erasableSyntaxOnly`.

## Como rodar

```bash
pnpm install
node bin/executar_testes.ts
pnpm typecheck            # tsc --noEmit
# ou, da raiz do monorepo:
pnpm test:typescript
```

Para depurar um ataque:

```bash
node bin/testar_um.ts AtaqueIdaEVolta
```

## Uso da cifra

A chave é lida de `process.env.FBC_KEY`:

```ts
process.env.FBC_KEY = 'uma-chave-de-32-bytes-aqui-ok!!';

import { encrypt, decrypt } from './src/Core/Criptografia.ts';
const token = encrypt('texto secreto');
const texto = decrypt(token);
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também exporta `base64urlEncode`, `base64urlDecode` e `_internal`
(`gerarKeystream`, `checksum`, `rotEsquerda8`, `rotEsquerda32`).

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.ts` implementando `AtaqueInterface`:

```ts
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

export class AtaqueX implements AtaqueInterface {
  nome(): string {
    return 'Nome exibido no relatório';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    // ... seu ataque ...
    // throw new SkipAtaqueException('...') se o alvo não suportar
    return new ResultadoAtaque(this.nome(), false, 'info', 'detalhes');
  }
}
```

Registre em `bin/executar_testes.ts`:

```ts
suite.adicionar(new AtaqueX());
```

## Notas

- `verbatimModuleSyntax`: use `import type` para tipos e `import` normal para
  classes/valores.
- `erasableSyntaxOnly`: sem `enum`, `namespace` ou parameter properties no
  construtor.
- `catch (e)`: `e` é `unknown`; use `e instanceof Error ? e.message : String(e)`.
- Dados binários são `Buffer`; `encrypt` aceita `string | Buffer` para os testes
  com bytes arbitrários.
- `Util.ts` tem `randomInt`, `randomBytes`, `bitsDiferentes`, `contarBits1`,
  `shuffle` e `arrayRandKey`.

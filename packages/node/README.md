# Criptografia FBC — Node.js

![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=nodedotjs&logoColor=white)

Implementação da cifra caseira **FBC** em Node.js, com a suíte de 50 ataques
criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

## Requisitos

- Node.js 20+

## Estrutura

```
src/
├── Core/Criptografia.js           # encrypt / decrypt + _internal
└── Seguranca/
    ├── CriptografiaAlvo.js        # liga a suíte à cifra (usa _internal)
    ├── ResultadoAtaque.js
    ├── SkipAtaqueException.js
    ├── SuiteDeAtaques.js
    ├── Util.js
    └── Ataques/*.js               # 50 ataques
bin/executar_testes.js             # runner da suíte
```

CommonJS (`require` / `module.exports`), sem dependências externas.

## Como rodar

```bash
node bin/executar_testes.js
# ou, da raiz do monorepo:
pnpm test:node
```

## Uso da cifra

A chave é lida de `process.env.FBC_KEY`:

```js
process.env.FBC_KEY = 'uma-chave-de-32-bytes-aqui-ok!!';

const { encrypt, decrypt } = require('./src/Core/Criptografia.js');
const token = encrypt('texto secreto');
const texto = decrypt(token);
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também exporta `base64urlEncode`, `base64urlDecode` e `_internal`
(`gerarKeystream`, `checksum`, `rotEsquerda8`, `rotEsquerda32`), usado pelo
`CriptografiaAlvo` para os ataques de baixo nível.

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.js`:

```js
'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');

class AtaqueX {
  nome() {
    return 'Nome exibido no relatório';
  }

  executar(alvo) {
    // ... seu ataque ...
    // throw new SkipAtaqueException('...') se o alvo não suportar
    return new ResultadoAtaque(this.nome(), false, 'info', 'detalhes');
  }
}

module.exports = AtaqueX;
```

Registre em `bin/executar_testes.js`:

```js
suite.adicionar(new AtaqueX());
```

## Notas

- Dados binários são `Buffer`; `gerarKeystreamBruto`/`checksumBruto` esperam e
  devolvem `Buffer`.
- A chave deve ter exatamente 32 bytes.
- `Util.js` tem `randomInt`, `randomBytes`, `bitsDiferentes`, `contarBits1`,
  `shuffle` e `arrayRandKey`.

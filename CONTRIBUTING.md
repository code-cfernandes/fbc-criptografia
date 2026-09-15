# Contribuindo

Obrigado pelo interesse. Este é um projeto educacional: a cifra "FBC" é
implementada em dez linguagens (PHP, Node.js, TypeScript, Python, Bash, Java,
Go, Rust, Dart e Julia) e uma mesma suíte de **50 ataques** roda contra todas. O
objetivo é manter todas **compatíveis byte a byte** e a suíte **verde**.

## Pré-requisitos

| Ferramenta | Versão |
| --- | --- |
| PHP + Composer | 8.3+ |
| Node.js + pnpm | 24+ / 11+ (TypeScript roda sem build) |
| Python | 3.12+ |
| Bash | 4.3+ |
| Java | 21+ |
| Go | 1.27+ |
| Rust | 1.98+ (linker `cc`) |
| Dart | 3.13+ |
| Julia | 1.13+ |

## Rodando os testes

```bash
pnpm install
pnpm test                 # tudo: ataques + fuzz cruzado + regressão (consolidado)
pnpm test --detalhado     # inclui a saída completa de cada frente
pnpm test:bruto           # saída crua só da suíte de ataques (pnpm -r --no-bail test)
pnpm test:php             # ou test:node / test:typescript / test:python / test:bash
pnpm test:java            # ou test:go / test:rust / test:dart / test:julia
pnpm typecheck:typescript # tsc --noEmit do pacote TS
pnpm fuzz                 # fuzzing cruzado isolado
pnpm regressao            # regressão histórica isolada
pnpm fuzz:memoria         # fuzzing de memória (Go + Rust), 5 min
pnpm lint                 # análise estática (linters + SAST + dependências)
```

Ao adicionar um ataque novo, adicione também o caso correspondente ao harness de
regressão histórica se ele corrige/previne um bug conhecido, e garanta que
`pnpm fuzz` e `pnpm regressao` continuam verdes.

### Análise estática

Duas frentes, ambas no GitHub Actions (push/PR na `main`):

- **CodeQL** (`.github/workflows/codeql.yml`): JS/TS, Python, Go e Java; os
  resultados aparecem em **Security → Code scanning**. Se alterar o build de um
  desses pacotes, ajuste o passo de build correspondente no workflow.
- **Linters/SAST/dependências** (`.github/workflows/analise.yml`): ShellCheck
  (Bash), Clippy + cargo-audit (Rust), PHPStan (PHP), dart analyze (Dart),
  JET/Aqua (Julia), Semgrep, Gitleaks e OSV-Scanner. Roda localmente com
  `pnpm lint` (relatório consolidado).

Ao adicionar um ataque novo em uma linguagem coberta, garanta que `pnpm lint`
continua verde (rode antes do commit). Se introduzir uma dependência, o
`minimumReleaseAge` do pnpm pode bloquear versões muito recentes — nesse caso,
aguarde ou adicione uma exceção justificada em `pnpm-workspace.yaml`.

Cada suíte imprime um relatório e termina com código de saída `0` quando nenhum
ataque encontra vulnerabilidade.

Para rodar um ataque isolado durante o desenvolvimento:

```bash
# PHP
php -r 'require "packages/php/vendor/autoload.php"; ...'
# Node
node -e '...'
# Python
python3 -c '...'
# Bash
bash packages/bash/bin/testar_um.sh AtaqueIdaEVolta
```

## Adicionando um novo ataque

Um ataque recebe um **alvo** (`CriptografiaAlvo`) e devolve um `ResultadoAtaque`.
O alvo expõe:

- `encrypt(texto)` / `decrypt(token)`
- `prefixo()` / `tamanhoIv()`
- `decompor(tokenDecodificado)` / `recompor(campos)`
- `gerarKeystreamBruto(key, iv, proposito, tamanho)` / `checksumBruto(dados, key)`
- `chaveDeTeste()` / `base64urlEncode` / `base64urlDecode`

Se o alvo não expuser o recurso necessário, o ataque deve **pular** (e não
falhar). Depois de criar o arquivo, registre-o no runner
(`bin/executar_testes.*`) na ordem desejada.

### PHP

Crie `packages/php/src/Seguranca/Ataques/AtaqueX.php` implementando
`Application\Seguranca\AtaqueInterface`:

```php
<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

class AtaqueX implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Nome exibido no relatório';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        // ... seu ataque ...
        return new ResultadoAtaque($this->nome(), false, 'info', 'detalhes');
    }
}
```

Registre em `packages/php/bin/executar_testes.php`:
`->adicionar(new AtaqueX())`.

### Node.js

Crie `packages/node/src/Seguranca/Ataques/AtaqueX.js`:

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
    return new ResultadoAtaque(this.nome(), false, 'info', 'detalhes');
  }
}

module.exports = AtaqueX;
```

Registre em `packages/node/bin/executar_testes.js` com
`.adicionar(new AtaqueX())`.

### TypeScript

Crie `packages/typescript/src/Seguranca/Ataques/AtaqueX.ts` implementando
`AtaqueInterface`:

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
    return new ResultadoAtaque(this.nome(), false, 'info', 'detalhes');
  }
}
```

Registre em `packages/typescript/bin/executar_testes.ts` com
`.adicionar(new AtaqueX())` e rode `pnpm typecheck` (strict +
`verbatimModuleSyntax` + `erasableSyntaxOnly`).

### Python

Crie `packages/python/src/Seguranca/Ataques/AtaqueX.py`:

```python
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueX:
    def nome(self) -> str:
        return "Nome exibido no relatório"

    def executar(self, alvo) -> ResultadoAtaque:
        # ... seu ataque ...
        return ResultadoAtaque(self.nome(), False, "info", "detalhes")
```

Registre em `packages/python/bin/executar_testes.py` com `.adicionar(AtaqueX())`.

### Bash

Crie `packages/bash/src/Seguranca/Ataques/AtaqueX.sh` definindo uma função com o
nome do ataque (o arquivo é `source`ado; **não** faça `source` nem `exit`):

```bash
AtaqueX() {
    ATQ_NOME="Nome exibido no relatório"

    # ... seu ataque ...
    # use res_resistiu / res_vulneravel / res_demonstracao / res_skip / res_erro
    res_resistiu "detalhes" "info"
    return 0
}
```

Registre o nome da função no array `ATAQUES` em
`packages/bash/bin/executar_testes.sh`.

### Java / Go / Rust / Dart / Julia

Essas linguagens têm a cifra, a infraestrutura e os 50 ataques. O padrão é o
mesmo (um alvo + `nome()`/`executar(alvo)` + registro no runner), mas com o
layout idiomático de cada uma:

- Java: `src/main/java/fbc/Seguranca/Ataques/AtaqueX.java` (implementa `AtaqueInterface`), registre em `Main.java`.
- Go: `internal/seguranca/ataques/ataque_x.go` (interface `Ataque`), registre em `cmd/executar/main.go`.
- Rust: `src/seguranca/ataques/ataque_x.rs` (trait `Ataque`), registre em `src/main.rs`.
- Dart: `lib/Seguranca/Ataques/AtaqueX.dart` (estende `Ataque`), registre em `bin/executar_testes.dart`.
- Julia: `src/Seguranca/Ataques/AtaqueX.jl` (subtipo de `Ataque`), registre em `bin/executar_testes.jl`.

Veja o README de cada pacote para detalhes. Novos ataques devem ser portados
com os mesmos nomes e limiares em todas as linguagens.

## Convenções

- Mantenha os comentários e mensagens em **português**.
- Preserve a compatibilidade **byte a byte** entre as implementações. Ao mudar a
  cifra, mude em todas e verifique o vetor de referência do
  `AtaqueVetorDeterministico` (chave `"K"` × 32, IV zero, propósito `enc`,
  32 bytes): `219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249`.
- Dados binários: use `Buffer` (Node), `bytes`/`bytearray` (Python), arrays de
  decimais (Bash) e strings binárias (PHP). Evite tratar binário como texto.
- Ataques devem ser **determinísticos o suficiente** para não gerar falsos
  positivos. Ao reduzir amostras (necessário no Bash), reescale limiares
  estatísticos proporcionalmente a `1/sqrt(n)`.
- No Bash, use `awk` para ponto flutuante e a global `FBC_ESCALA` para escalar
  amostras.
- Não comite segredos: o `.env` é ignorado pelo git.

## Versionamento (SemVer)

Todos os pacotes compartilham a mesma versão (versionamento travado), no formato
`MAJOR.MINOR.PATCH`:

- **MAJOR**: mudanças incompatíveis (ex.: alterar o formato do token ou o
  contrato dos ataques de forma que quebre quem consome).
- **MINOR**: novas funcionalidades compatíveis (ex.: novos ataques, nova
  linguagem).
- **PATCH**: correções compatíveis (ex.: corrigir um ataque, ajustar limiar).

Para bumpar a versão de tudo de uma vez:

```bash
pnpm versao patch    # ou minor / major / 1.2.3
```

O script atualiza o `package.json` da raiz, de cada pacote e o `composer.json` do
PHP. Toda mudança relevante deve ser registrada em [CHANGELOG.md](CHANGELOG.md).

## Checklist antes de abrir um PR

- [ ] O novo ataque está registrado no runner da(s) linguagem(ns) afetada(s).
- [ ] `pnpm test` passa em todas as linguagens.
- [ ] `pnpm typecheck:typescript` passa sem erros nem casts desnecessários.
- [ ] Se a cifra mudou, o vetor de referência é o mesmo em todas.
- [ ] Nomes e mensagens em português, sem segredos.
- [ ] A versão foi bumpada (`pnpm versao ...`) e o `CHANGELOG.md` atualizado.

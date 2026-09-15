# Criptografia FBC

![PHP](https://img.shields.io/badge/PHP-8.3+-777BB4?logo=php&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=nodedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-7+-3178C6?logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4.3+-4EAA25?logo=gnubash&logoColor=white)
![Java](https://img.shields.io/badge/Java-21+-ED8B00?logo=openjdk&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-1.98+-000000?logo=rust&logoColor=white)
![Dart](https://img.shields.io/badge/Dart-3.13+-0175C2?logo=dart&logoColor=white)
![Julia](https://img.shields.io/badge/Julia-1.13+-9558B2?logo=julia&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-workspace-F69220?logo=pnpm&logoColor=white)
![ataques](https://img.shields.io/badge/ataques-50%2F50-success)
![versão](https://img.shields.io/badge/vers%C3%A3o-1.2.0-blue)
[![CodeQL](https://github.com/code-cfernandes/fbc-criptografia/actions/workflows/codeql.yml/badge.svg)](https://github.com/code-cfernandes/fbc-criptografia/actions/workflows/codeql.yml)

Monorepo educacional com a mesma cifra caseira ("FBC") implementada em dez
pacotes — **PHP, Node.js, TypeScript, Python, Bash, Java, Go, Rust, Dart e
Julia** — e uma suíte com **50 ataques criptográficos** que roda contra cada
implementação. Todas as dez linguagens estão em paridade: **50/50 ataques** e o
mesmo vetor de referência byte a byte.

> **Aviso:** é uma cifra caseira, feita para estudo e para exercitar o raciocínio
> de criptoanálise. Ela **não** foi revisada e **não** deve ser usada em produção.
> Para qualquer uso real, use bibliotecas consagradas (libsodium, AES-GCM, etc.).

## Formato do token

```
FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
```

- **integridade** — MAC caseiro de 32 bytes (8 rodadas de um checksum estilo FNV,
  com finalização para evitar avalanche fraca nos últimos bytes).
- **ciphertext** — texto cifrado por XOR com o keystream.
- **iv** — 16 bytes aleatórios por operação.

O keystream é gerado em blocos de 32 bytes por uma recorrência tipo-Fibonacci
seguida de uma rede de difusão "butterfly" (distâncias que dobram: 3, 5, 11, 19,
41, repetidas), com rotações derivadas dos dígitos de Pi. A chave participa de
cada rodada, e não apenas do estado inicial.

A chave deve ter exatamente **32 bytes** e é lida da variável de ambiente
`FBC_KEY`.

## Requisitos

| Ferramenta | Versão |
| --- | --- |
| PHP + Composer | 8.3+ |
| Node.js + pnpm | 20+ / 11+ |
| Python | 3.12+ |
| Bash | 4.3+ (namerefs) |
| Java | 21+ |
| Go | 1.27+ |
| Rust | 1.98+ (linker `cc`) |
| Dart | 3.13+ |
| Julia | 1.13+ |

## Estrutura

```
.
├── package.json            # raiz do workspace pnpm
├── pnpm-workspace.yaml
└── packages/
    ├── php/         src/Core  src/Seguranca/{Ataques}  bin  tests
    ├── node/        src/Core  src/Seguranca/{Ataques}  bin
    ├── typescript/  src/Core  src/Seguranca/{Ataques}  bin
    ├── python/      src/Core  src/Seguranca/{Ataques}  bin
    ├── bash/        src/Core  src/Seguranca/{Ataques}  bin
    ├── java/        src/main/java/fbc/{Core,Seguranca/Ataques}  bin
    ├── go/          internal/{core,seguranca/Ataques}  cmd/executar
    ├── rust/        src/{core,seguranca/Ataques}
    ├── dart/        lib/{Core,Seguranca/Ataques}  bin
    └── julia/       src/{Core,Seguranca/Ataques}  bin
```

| Pacote | Linguagem | Ataques | README |
| --- | --- | --- | --- |
| `packages/php` | PHP 8.3+ | 50 | [README](packages/php/README.md) |
| `packages/node` | Node.js 20+ | 50 | [README](packages/node/README.md) |
| `packages/typescript` | TypeScript 7+ | 50 | [README](packages/typescript/README.md) |
| `packages/python` | Python 3.12+ | 50 | [README](packages/python/README.md) |
| `packages/bash` | Bash 4.3+ | 50 | [README](packages/bash/README.md) |
| `packages/java` | Java 21+ | 50 | [README](packages/java/README.md) |
| `packages/go` | Go 1.27+ | 50 | [README](packages/go/README.md) |
| `packages/rust` | Rust 1.98+ | 50 | [README](packages/rust/README.md) |
| `packages/dart` | Dart 3.13+ | 50 | [README](packages/dart/README.md) |
| `packages/julia` | Julia 1.13+ | 50 | [README](packages/julia/README.md) |

Todos os pacotes têm a mesma arquitetura conceitual: uma pasta `Core` com a
cifra, uma pasta `Seguranca` com a infraestrutura da suíte (`CriptografiaAlvo`,
`ResultadoAtaque`, `SuiteDeAtaques`, utilitários) e uma pasta `Ataques` com os
ataques, além de um runner (`bin/executar_testes.*`, `cmd/executar`, etc.) que
imprime o relatório. Os caminhos exatos seguem o layout idiomático de cada
linguagem (mostrado acima).

## Como rodar

Instale o workspace:

```bash
pnpm install
```

Rode todas as frentes de teste. O `pnpm test` executa, para cada linguagem, a
suíte de 50 ataques, depois o fuzzing cruzado e a regressão histórica, e imprime
um **relatório consolidado** no final (continua mesmo se uma frente falhar):

```bash
pnpm test                # tudo: ataques + fuzz cruzado + regressão
pnpm test --detalhado    # inclui a saída completa de cada frente
pnpm test:bruto          # pnpm -r --no-bail test (saída crua só da suíte de ataques)
```

O relatório consolidado traz a tabela por linguagem (ataques, vulnerabilidades,
tempo, status) e uma linha de resumo para o fuzzing cruzado e para a regressão,
com um **RESUMO GERAL** no fim.

Para rodar cada frente isoladamente (ou o fuzzing de memória, que não entra no
`pnpm test`):

```bash
pnpm fuzz            # fuzzing cruzado: 1000 casos idênticos nas 10 linguagens
pnpm regressao       # regressão histórica: a suíte ainda pega os 6 bugs já corrigidos
pnpm fuzz:memoria    # fuzzing de memória (Go + Rust) por 5 min, sem crashes
pnpm lint            # análise estática (linters + SAST + dependências)
```

Ou individualmente:

```bash
pnpm test:php
pnpm test:node
pnpm test:typescript
pnpm test:python
pnpm test:bash
pnpm test:java
pnpm test:go
pnpm test:rust
pnpm test:dart
pnpm test:julia
```

### PHP

```bash
cd packages/php
composer install
composer suite        # suíte de ataques (bin/executar_testes.php)
composer test         # ida-e-volta básica (bin/runTest.php)
```

### Node.js

```bash
cd packages/node
node bin/executar_testes.js
```

### TypeScript

Roda `.ts` direto no Node 24 (type stripping), sem build. O `tsc` é usado só
para checagem de tipos.

```bash
cd packages/typescript
node bin/executar_testes.ts
pnpm typecheck          # tsc --noEmit
```

### Python

```bash
cd packages/python
python3 bin/executar_testes.py
```

### Bash

```bash
cd packages/bash
bash bin/executar_testes.sh
FBC_ESCALA=10 bash bin/executar_testes.sh   # mais amostras (mais lento)
```

O bash usa amostras reduzidas por padrão (é ordens de magnitude mais lento). A
variável `FBC_ESCALA` multiplica esses defaults.

### Java

```bash
cd packages/java
bash bin/executar_testes.sh   # compila (javac) e roda
```

### Go

```bash
cd packages/go
go run ./cmd/executar
```

### Rust

```bash
cd packages/rust
cargo run --quiet
```

### Dart

```bash
cd packages/dart
dart run bin/executar_testes.dart
```

### Julia

```bash
cd packages/julia
julia --startup-file=no bin/executar_testes.jl
```

## Uso da cifra

PHP (`namespace Application\Core`):

```php
putenv('FBC_KEY=uma-chave-de-32-bytes-aqui-ok!!');

$token = Application\Core\Criptografia::encrypt('texto secreto');
$texto = Application\Core\Criptografia::decrypt($token);
```

Node.js:

```js
process.env.FBC_KEY = 'uma-chave-de-32-bytes-aqui-ok!!';

const { encrypt, decrypt } = require('./packages/node/src/Core/Criptografia.js');
const token = encrypt('texto secreto');
const texto = decrypt(token);
```

TypeScript (ESM, sem build):

```ts
process.env.FBC_KEY = 'uma-chave-de-32-bytes-aqui-ok!!';

import { encrypt, decrypt } from './packages/typescript/src/Core/Criptografia.ts';
const token = encrypt('texto secreto');
const texto = decrypt(token);
```

Python:

```python
import os
os.environ['FBC_KEY'] = 'uma-chave-de-32-bytes-aqui-ok!!'

# execute a partir de packages/python (ou adicione a raiz do pacote ao sys.path)
from src.Core.Criptografia import encrypt, decrypt
token = encrypt('texto secreto')
texto = decrypt(token)
```

Bash:

```bash
export FBC_KEY='uma-chave-de-32-bytes-aqui-ok!!'

./packages/bash/src/Core/Criptografia.sh encrypt "texto secreto"
./packages/bash/src/Core/Criptografia.sh decrypt "FBC..."
```

## Suíte de ataques

Cada ataque implementa `nome()` e `executar(alvo)`, devolvendo um
`ResultadoAtaque` (`vulneravel`, `severidade`, `detalhes`). A suíte imprime um
relatório e retorna código de saída diferente de zero quando encontra alguma
vulnerabilidade.

Os 50 ataques:

1. Ida-e-volta (round trip)
2. Ida-e-volta com dados binários (inclui NUL)
3. Mensagens longas (multi-bloco)
4. Adulteração de bits (integridade)
5. Colisão no checksum (paradoxo do aniversário)
6. Linearidade e diferenciais do checksum
7. Confusão de campos do token (reordenação/deslocamento)
8. Canonicalização do token (base64 não-canônico)
9. Tokens malformados (fuzzing de entrada)
10. Colisão de IV
11. IVs degenerados (zero, 0xFF, alternado)
12. Entropia e previsibilidade do IV
13. Reuso forçado de IV (two-time pad) — demonstração
14. Separação chave/IV (invariância a key XOR iv)
15. Diferencial do keystream (delta fixo no IV)
16. Cobertura de dependência do IV (entrada x saída)
17. Efeito avalanche
18. Efeito avalanche da chave
19. Efeito avalanche do checksum/MAC
20. Cobertura de dependência (matriz entrada x saída)
21. Fold estrutural (metades/quartos/oitavos repetidos)
22. Correlação entre posições do bloco
23. Distribuição de bytes por posição do bloco
24. Integral (soma balanceada variando 1 byte de IV/chave)
25. Distribuição de bytes (qui-quadrado)
26. Autocorrelação e periodicidade do keystream
27. Bateria estatística de bits (monobit/runs/blocos)
28. Teste serial (padrões de bits sobrepostos)
29. Somas cumulativas (cusum)
30. Entropia aproximada (ApEn vs controle aleatório)
31. Complexidade linear (Berlekamp-Massey)
32. Previsibilidade de bits (preditor por contexto)
33. Correlação entre ciphertexts do mesmo plaintext
34. Independência entre keystreams de propósitos diferentes (enc x mac)
35. Validação do tamanho da chave
36. Rejeição de chave incorreta
37. Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)
38. Determinismo (vetor de referência key/iv fixos)
39. Timing da verificação de integridade
40. Bytes fixos entre tokens
41. Interoperabilidade e vetores conhecidos (KAT)
42. SAC (Strict Avalanche Criterion)
43. BIC (Bit Independence Criterion)
44. Chave relacionada (related-key)
45. Rotacional/slide (simetria por rotação)
46. Chaves fracas (busca dirigida)
47. Aproximação linear (viés de Walsh)
48. Estatística do ciphertext (chi²/runs/autocorrelação)
49. Força bruta e truncamento do MAC
50. Length extension / truncamento de token

## Frentes de teste

O `pnpm test` roda as três primeiras frentes e consolida tudo num único
relatório; o fuzzing de memória (`pnpm fuzz:memoria`) é separado porque leva
~5 min por linguagem.

### Suíte de ataques — `pnpm test`

50 ataques por linguagem, com relatório consolidado (ataques, vulnerabilidades,
tempo e status).

### Fuzzing cruzado — `pnpm fuzz`

Gera 1000 casos determinísticos (`fuzz/casos.txt`, no formato
`chave_hex|iv_hex|proposito|plaintext_hex`), roda o runner de cada linguagem
calculando keystream + checksum e compara as 10 saídas linha a linha. Cobre
tamanhos de borda (0, 1, 31, 32, 33, 63, 64, 65, 1000 bytes), chaves/IVs
degenerados e bytes `0x00` no meio do plaintext. `pnpm fuzz --casos N` ajusta o
volume.

### Regressão histórica — `pnpm regressao`

Prova que a suíte ainda detecta os bugs reais já corrigidos: para cada bug, um
snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la, enquanto o
código atual PRECISA resistir. Cobre 6 bugs (keystream ignorando o IV,
combinador simétrico, checksum sem finalização, poucas rodadas de difusão,
chave só no estado inicial e base64 não estrito) e, no bash, a preservação de
NUL.

### Fuzzing de memória — `pnpm fuzz:memoria`

`go test -fuzz` e `cargo fuzz` (nightly) no decodificador de token com bytes
arbitrários, por 5 minutos cada, esperando zero panics. O Rust roda sem
sanitizer por não haver `gcc`/`clang` no ambiente. Aceita a duração em segundos:
`pnpm fuzz:memoria 60`.

## Análise estática

Há duas frentes, ambas rodando no GitHub Actions em `push`/`pull_request` na
`main`, e também localmente.

### CodeQL — `.github/workflows/codeql.yml`

SAST do GitHub; publica os resultados em **Security → Code scanning**. Cobre as
linguagens suportadas pelo CodeQL:

| Linguagem CodeQL | Pacotes | Build |
| --- | --- | --- |
| `javascript-typescript` | `packages/node`, `packages/typescript` | nenhum |
| `python` | `packages/python` | nenhum |
| `go` | `packages/go` | `go build ./...` |
| `java-kotlin` | `packages/java` | `javac` |

Configuração (exclusões e suíte `security-extended`) em
`.github/codeql/codeql-config.yml`.

### Linters, SAST e dependências — `pnpm lint`

Cobre as linguagens que o CodeQL não atende (PHP, Rust, Dart, Julia e Bash) e
adiciona SAST, segredos e auditoria de dependências. Roda via
`.github/workflows/analise.yml` ou localmente com `pnpm lint`:

| Checagem | Ferramenta | Cobre |
| --- | --- | --- |
| `bash (ShellCheck)` | ShellCheck | Bash |
| `rust (Clippy)` | Clippy | Rust |
| `rust (cargo-audit)` | cargo-audit | CVEs do `Cargo.lock` |
| `php (PHPStan)` | PHPStan (nível 6) | PHP |
| `php (composer audit)` | Composer | CVEs do `composer.lock` |
| `dart (dart analyze)` | analyzer oficial | Dart |
| `julia (JET + Aqua)` | JET.jl + Aqua.jl | Julia |
| `SAST (Semgrep)` | Semgrep OSS (`p/default`) | multi-linguagem |
| `segredos (Gitleaks)` | Gitleaks | segredos no git |
| `deps (OSV-Scanner)` | OSV-Scanner | todos os lockfiles |

O `pnpm lint` imprime um relatório consolidado (checagem, tempo e status) e sai
com código `!= 0` se alguma checagem falhar. Cada pacote também expõe o seu
linter isolado (`pnpm --filter @criptografia/<lang> run lint|analyse|audit`).

## Como escrever um novo ataque

O contrato é o mesmo nas dez linguagens: um ataque expõe um nome e um método
`executar(alvo)` que devolve um `ResultadoAtaque` (vulnerável, severidade,
detalhes). Ele recebe um **alvo** (`CriptografiaAlvo`) que abstrai a cifra e
oferece:

- `encrypt` / `decrypt`
- `prefixo` / `tamanhoIv`
- `decompor` / `recompor` (campos do token)
- `gerarKeystreamBruto` e `checksumBruto` (camadas internas)
- `chaveDeTeste`, `base64urlEncode` / `base64urlDecode`

Se o alvo não expuser o que o ataque precisa, sinalize um **skip** — a suíte
marca o ataque como "pulado" em vez de falhar.

Resumo por linguagem (detalhes no README de cada pacote):

| Linguagem | Arquivo | Contrato |
| --- | --- | --- |
| PHP | `src/Seguranca/Ataques/AtaqueX.php` | implementa `AtaqueInterface` (`nome`, `executar`) |
| Node | `src/Seguranca/Ataques/AtaqueX.js` | classe com `nome()` e `executar(alvo)` |
| TypeScript | `src/Seguranca/Ataques/AtaqueX.ts` | classe que implementa `AtaqueInterface` |
| Python | `src/Seguranca/Ataques/AtaqueX.py` | classe com `nome()` e `executar(alvo)` |
| Bash | `src/Seguranca/Ataques/AtaqueX.sh` | função `AtaqueX` que preenche `ATQ_*` |
| Java | `src/main/java/fbc/Seguranca/Ataques/AtaqueX.java` | implementa `AtaqueInterface` |
| Go | `internal/seguranca/ataques/ataque_x.go` | implementa a interface `Ataque` |
| Rust | `src/seguranca/ataques/ataque_x.rs` | implementa o trait `Ataque` |
| Dart | `lib/Seguranca/Ataques/AtaqueX.dart` | estende a classe abstrata `Ataque` |
| Julia | `src/Seguranca/Ataques/AtaqueX.jl` | subtipo do tipo abstrato `Ataque` |

Depois de criar o arquivo, registre o ataque no runner (`bin/executar_testes.*`)
e rode a suíte. O passo a passo completo (testes locais, estilo e checklist) está
em [CONTRIBUTING.md](CONTRIBUTING.md).

## Resultado atual

Todas as frentes estão verdes na versão **1.2.0**:

| Frente | Escopo | Resultado |
| --- | --- | --- |
| Suíte de ataques — `pnpm test` | 50 ataques × 10 linguagens | **500/500**, 0 vulnerabilidades |
| Fuzzing cruzado — `pnpm fuzz` | 1000 casos × 10 linguagens | **1000/1000** idênticos |
| Regressão histórica — `pnpm regressao` | 6 bugs × 10 linguagens + NUL (bash) | **60 detecções** + NUL |
| Fuzzing de memória — `pnpm fuzz:memoria` | Go + Rust, 5 min cada | **0 crashes** (Go ~64M, Rust ~340M execuções) |
| Análise estática — `pnpm lint` | 10 checagens (linters + SAST + deps) | **10/10** |
| CodeQL — workflow | JS/TS, Python, Go, Java | roda no GitHub Actions |

As dez implementações resistem aos 50 ataques. Como todas compartilham a mesma
lógica byte a byte, o vetor de referência (chave `"K"` × 32, IV zero, propósito
`enc`, 32 bytes) é idêntico em todas:

```
219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249
```

A interoperabilidade é verificada explicitamente: tokens gerados por qualquer
implementação decifram nas demais (ataque `AtaqueInteroperabilidade`), e o
fuzzing cruzado confirma 1000 entradas idênticas nas 10 linguagens.

## Notas de implementação

- **Distâncias de difusão dobradas** (`[3,5,11,19,41,3,5,11,19,41]`) em todas as
  linguagens: ajuste que faz o ataque integral (soma balanceada) deixar de
  distinguir a cifra de uma função aleatória.
- **Bash**: o `gerar_keystream` e o `checksum` têm as rotações e o "passo"
  embutidos nos laços (sem subshells), o que deixou a cifra ~24x mais rápida
  mantendo a saída byte a byte idêntica. Os ataques usam `awk` para ponto
  flutuante e amostras reduzidas.
- **TypeScript**: o pacote roda sem build (Node 24 faz type stripping dos `.ts`);
  o `tsc` entra só como `typecheck`. Os contratos (`AlvoCriptografico`,
  `AtaqueInterface`, `ResultadoAtaque`) são tipados, com `strict` +
  `erasableSyntaxOnly`.
- **`AtaqueIdaEVoltaBinario` no bash** testa os bytes 1..255: bash não representa
  NUL em strings.
- **PHP** usa autoload PSR-4 (`Application\` → `src/`) e o script
  `bin/runTest.php` carrega a chave via `.env` (veja `src/Env/DotEnv.php`).
- **Paridade total**: as dez linguagens cobrem os 50 ataques e o mesmo KAT;
  cada runner sai com código `!= 0` se achar vulnerabilidade.
- **Toolchains**: Go/Rust/Dart/Julia foram instalados user-local (sem root);
  Rust usa o linker `cc` (wrapper do `zig cc`) por não haver `gcc`/`clang` no
  sistema.

## Versionamento

O projeto segue [SemVer](https://semver.org/lang/pt-BR/) e mantém **todos os
pacotes na mesma versão** (versionamento travado). As mudanças ficam registradas
no [CHANGELOG.md](CHANGELOG.md).

Para atualizar a versão de todos os pacotes de uma vez:

```bash
pnpm versao patch     # 1.0.0 -> 1.0.1
pnpm versao minor     # 1.0.0 -> 1.1.0
pnpm versao major     # 1.0.0 -> 2.0.0
pnpm versao 1.2.3     # define uma versão explícita
```

O script (`scripts/bump-versao.mjs`, sem dependências) atualiza o `package.json`
da raiz, o de cada pacote e o `composer.json` do PHP, e imprime o que mudou.

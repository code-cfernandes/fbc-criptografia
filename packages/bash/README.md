# Criptografia FBC — Bash

![Bash](https://img.shields.io/badge/Bash-4.3+-4EAA25?logo=gnubash&logoColor=white)

Implementação da cifra caseira **FBC** em Bash puro, com a suíte de 40 ataques
criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

## Requisitos

- Bash 4.3+ (namerefs) e utilitários padrão (`od`, `base64`, `awk`, `sed`)

## Estrutura

```
src/
├── Core/Criptografia.sh           # cifra (encrypt / decrypt)
└── Seguranca/
    ├── ResultadoAtaque.sh         # helpers res_* e convenção ATQ_*
    ├── Util.sh                    # random, popcount, awk helpers
    ├── CriptografiaAlvo.sh        # liga a suíte à cifra
    ├── SuiteDeAtaques.sh
    └── Ataques/*.sh               # 40 ataques
bin/
├── executar_testes.sh             # runner da suíte
└── testar_um.sh                   # roda um ataque isolado
```

## Como rodar

```bash
bash bin/executar_testes.sh
FBC_ESCALA=10 bash bin/executar_testes.sh   # mais amostras (mais lento)
# ou, da raiz do monorepo:
pnpm test:bash
```

Para depurar um ataque:

```bash
bash bin/testar_um.sh AtaqueIdaEVolta
```

## Uso da cifra

A chave é lida de `FBC_KEY`:

```bash
export FBC_KEY='uma-chave-de-32-bytes-aqui-ok!!'

./src/Core/Criptografia.sh encrypt "texto secreto"
./src/Core/Criptografia.sh decrypt "FBC..."
```

Ou, dentro de um script:

```bash
source src/Core/Criptografia.sh
cripto_encrypt "texto secreto"
cripto_decrypt "FBC..."
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.sh` definindo **uma função com o nome do
ataque**. O arquivo é `source`ado pelo runner; **não** faça `source` nem `exit`:

```bash
AtaqueX() {
    ATQ_NOME="Nome exibido no relatório"

    # ... seu ataque ...
    # res_resistiu / res_vulneravel / res_demonstracao / res_skip / res_erro
    res_resistiu "detalhes" "info"
    return 0
}
```

Registre a função no array `ATAQUES` em `bin/executar_testes.sh`.

## Notas

- **Bytes são arrays de decimais** (0-255) passados como string separada por
  espaço (ex.: `"70 66 67"`), porque bash não representa `0x00` em strings.
- **Ponto flutuante** usa `awk` (helpers `util_div`, `util_pct`, `util_menor`,
  `util_maior`, `util_fmt`).
- **Amostras reduzidas** por padrão (bash é muito mais lento). `FBC_ESCALA`
  multiplica os defaults; ao aumentar, reescale limiares estatísticos.
- **NUL**: `AtaqueIdaEVoltaBinario` testa os bytes 1..255 (NUL é irrepresentável).
- O `gerar_keystream` e o `checksum` têm o "passo" e as rotações embutidos nos
  laços (sem subshells), mantendo a saída idêntica às outras linguagens.

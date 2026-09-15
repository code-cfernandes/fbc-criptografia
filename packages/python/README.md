# Criptografia FBC — Python

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)

Implementação da cifra caseira **FBC** em Python, com a suíte de 40 ataques
criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

## Requisitos

- Python 3.12+

## Estrutura

```
src/
├── Core/Criptografia.py           # encrypt / decrypt + gerar_keystream/checksum
└── Seguranca/
    ├── CriptografiaAlvo.py        # liga a suíte à cifra
    ├── ResultadoAtaque.py
    ├── SkipAtaqueException.py
    ├── SuiteDeAtaques.py
    ├── Util.py
    └── Ataques/*.py               # 40 ataques
bin/executar_testes.py             # runner da suíte
```

Pacotes Python normais (com `__init__.py`) e imports relativos dentro de
`src/Seguranca`.

## Como rodar

```bash
python3 bin/executar_testes.py
# ou, da raiz do monorepo:
pnpm test:python
```

O runner adiciona a raiz do pacote ao `sys.path`, então pode ser chamado de
qualquer diretório. Se importar a cifra manualmente, rode a partir de
`packages/python` (ou ajuste o `sys.path`).

## Uso da cifra

A chave é lida de `FBC_KEY`:

```python
import os
os.environ['FBC_KEY'] = 'uma-chave-de-32-bytes-aqui-ok!!'

from src.Core.Criptografia import encrypt, decrypt
token = encrypt('texto secreto')
texto = decrypt(token)
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também expõe `gerar_keystream`, `checksum`, `base64url_encode` e
`base64url_decode`.

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.py`:

```python
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueX:
    def nome(self) -> str:
        return "Nome exibido no relatório"

    def executar(self, alvo) -> ResultadoAtaque:
        # ... seu ataque ...
        # raise SkipAtaqueException("...") se o alvo não suportar
        return ResultadoAtaque(self.nome(), False, "info", "detalhes")
```

Registre em `bin/executar_testes.py`:

```python
suite.adicionar(AtaqueX())
```

## Notas

- Dados binários são `bytes`/`bytearray`; indexar `bytes` devolve `int`.
- A chave deve ter exatamente 32 bytes (`len(key.encode("utf-8")) == 32`).
- `Util.py` tem `random_int`, `random_bytes`, `bits_diferentes`, `contar_bits1`,
  `shuffle` e `array_rand_key`.

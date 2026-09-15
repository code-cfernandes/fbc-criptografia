# Criptografia FBC — Rust

![Rust](https://img.shields.io/badge/Rust-1.98+-000000?logo=rust&logoColor=white)

Implementação da cifra caseira **FBC** em Rust, com a suíte de 8 ataques
criptográficos da fase 1. Faz parte do [monorepo Criptografia FBC](../../README.md).

Sem dependências externas (sem crates): o base64url é implementado à mão e os
bytes aleatórios vêm de `/dev/urandom` (com fallback por tempo + pid).

## Requisitos

- Rust 1.98+ (`cargo`/`rustc` no PATH)
- Linker: `cc` (wrapper de `zig cc`)

## Estrutura

```
src/
├── main.rs                          # runner da suíte
├── core/
│   ├── mod.rs
│   └── criptografia.rs              # encrypt / decrypt / keystream / checksum
└── seguranca/
    ├── mod.rs
    ├── alvo_criptografico.rs        # trait AlvoCriptografico + CamposToken
    ├── ataque.rs                    # trait Ataque + ErroAtaque
    ├── criptografia_alvo.rs         # liga a suíte à cifra
    ├── resultado_ataque.rs          # ResultadoAtaque + Severidade
    ├── suite_de_ataques.rs
    ├── util.rs
    └── ataques/*.rs                 # 8 ataques
```

## Como rodar

```bash
cargo run --quiet
# ou, da raiz do monorepo:
pnpm --filter @criptografia/rust test
```

O runner imprime o relatório no mesmo formato das outras linguagens e sai com
código `!= 0` se alguma vulnerabilidade for encontrada.

## Uso da cifra

A chave é lida de `FBC_KEY` e precisa ter exatamente 32 bytes. Dentro do
pacote, use o módulo `core::criptografia`:

```rust
std::env::set_var("FBC_KEY", "uma-chave-de-32-bytes-aqui-ok!!");

use crate::core::criptografia::{decrypt, encrypt};
let token = encrypt("texto secreto").unwrap();
let texto = decrypt(&token).unwrap();
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo `core::criptografia` também expõe `gerar_keystream`, `checksum`,
`base64url_encode`, `base64url_decode` e `random_bytes`.

## Como escrever um novo ataque

Crie `src/seguranca/ataques/ataque_x.rs` implementando o trait `Ataque`:

```rust
use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueX;

impl Ataque for AtaqueX {
    fn nome(&self) -> String {
        "Nome exibido no relatório".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        // ... seu ataque ...
        // Err(ErroAtaque::Skip("...".into())) se o alvo não suportar
        Ok(ResultadoAtaque::new(&self.nome(), false, Severidade::Info, "detalhes"))
    }
}
```

Registre em `src/seguranca/ataques/mod.rs` e em `src/main.rs`:

```rust
suite.adicionar(Box::new(AtaqueX));
```

## Notas

- Todos os bytes são `u8` e a aritmética usa `wrapping_*`, casando byte a byte
  com as implementações PHP/Node/TypeScript/Python/Bash.
- `AtaqueInteroperabilidade` fixa 8 keystreams e 4 tokens de referência (KAT);
  o vetor IV zero/`enc`/32 bytes é
  `219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249`.
- `ErroAtaque::Skip` corresponde à `SkipAtaqueException`; `ErroAtaque::Falha` a
  uma exceção inesperada.

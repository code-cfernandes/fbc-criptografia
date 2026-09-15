# Criptografia FBC — Julia

![Julia](https://img.shields.io/badge/Julia-1.13+-9558B2?logo=julia&logoColor=white)

Implementação da cifra caseira **FBC** em Julia, com a suíte de ataques
criptográficos (fase 1: 8 ataques). Faz parte do
[monorepo Criptografia FBC](../../README.md).

Sem dependências externas: usa apenas os stdlibs `Base64` e `Random`.

## Requisitos

- Julia 1.13+

## Estrutura

```
src/
├── CriptografiaFBC.jl             # módulo principal (includes + exports)
├── Core/Criptografia.jl           # encrypt / decrypt + gerar_keystream/checksum
└── Seguranca/
    ├── AlvoCriptografico.jl       # tipo abstrato do alvo
    ├── Ataque.jl                  # tipo abstrato Ataque (nome + executar)
    ├── CriptografiaAlvo.jl        # liga a suíte à cifra
    ├── ResultadoAtaque.jl
    ├── SkipAtaqueException.jl
    ├── SuiteDeAtaques.jl
    ├── Util.jl
    └── Ataques/*.jl               # 8 ataques
bin/executar_testes.jl             # runner da suíte
```

## Como rodar

```bash
julia --startup-file=no bin/executar_testes.jl
# ou, da raiz do monorepo:
pnpm --filter @criptografia/julia test
```

O runner sai com código `0` quando nenhuma vulnerabilidade é encontrada e `1`
caso contrário.

## Uso da cifra

A chave é lida de `FBC_KEY` e precisa ter exatamente 32 bytes:

```julia
ENV["FBC_KEY"] = "uma-chave-de-32-bytes-aqui-ok!!"

include("src/CriptografiaFBC.jl")
using .CriptografiaFBC

token = encrypt("texto secreto")
texto = decrypt(token)
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também exporta `gerar_keystream`, `checksum`, `base64url_encode`,
`base64url_decode`, `rot_esquerda8` e `rot_esquerda32`.

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.jl`:

```julia
struct AtaqueX <: Ataque end

nome(::AtaqueX) = "Nome exibido no relatório"

function executar(a::AtaqueX, alvo::AlvoCriptografico)
    # ... seu ataque ...
    # throw(SkipAtaqueException("...")) se o alvo não suportar
    return ResultadoAtaque(nome(a), false, "info", "detalhes")
end
```

Registre em `src/CriptografiaFBC.jl` (no `include` e no `export`) e em
`bin/executar_testes.jl`:

```julia
adicionar(suite, AtaqueX())
```

## Notas

- Dados binários são `Vector{UInt8}`; indexação é 1-based.
- A aritmética de bytes usa `Int` com máscara `& 0xFF` para reproduzir o
  comportamento das outras linguagens.
- `Util.jl` tem `random_int`, `random_bytes`, `bits_diferentes`, `contar_bits1`,
  `shuffle_array` e `array_rand_key`.

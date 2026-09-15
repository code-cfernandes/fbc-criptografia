# Criptografia FBC — Go

![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)

Implementação da cifra caseira **FBC** em Go, com a suíte de ataques
criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

Usa somente a biblioteca padrão (sem dependências externas).

## Requisitos

- Go 1.27+

## Estrutura

```
internal/
├── core/Criptografia.go            # encrypt / decrypt + GerarKeystream/Checksum
└── seguranca/
    ├── AlvoCriptografico.go        # interface do alvo + CamposToken
    ├── Ataque.go                   # interface dos ataques
    ├── CriptografiaAlvo.go         # liga a suíte à cifra
    ├── ResultadoAtaque.go
    ├── SkipAtaqueException.go
    ├── SuiteDeAtaques.go
    ├── Util.go
    └── Ataques/*.go                # ataques
cmd/executar/main.go                # runner da suíte
```

## Como rodar

```bash
go run ./cmd/executar
# ou, da raiz do monorepo:
pnpm --filter @criptografia/go test
```

## Uso da cifra

A chave é lida de `FBC_KEY`:

```go
os.Setenv("FBC_KEY", "uma-chave-de-32-bytes-aqui-ok!!")

token, _ := core.Encrypt([]byte("texto secreto"))
texto, _ := core.Decrypt(token)
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O pacote `internal/core` também exporta `GerarKeystream`, `Checksum`,
`Base64urlEncode` e `Base64urlDecode`.

## Como escrever um novo ataque

Crie `internal/seguranca/ataques/ataque_x.go` implementando `seguranca.Ataque`:

```go
type AtaqueX struct{}

func (a *AtaqueX) Nome() string { return "Nome exibido no relatório" }

func (a *AtaqueX) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	// ... seu ataque ...
	// return seguranca.ResultadoAtaque{}, seguranca.NovoSkip("...") se o alvo não suportar
	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   "detalhes",
	}, nil
}
```

Registre em `cmd/executar/main.go`:

```go
suite.Adicionar(&ataques.AtaqueX{})
```

## Notas

- Dados binários são `[]byte`; a chave deve ter exatamente 32 bytes.
- `Util.go` tem `RandomInt`, `RandomBytes`, `BitsDiferentes`, `ContarBits1`,
  `ContarBitsBuffer` e `Shuffle`.
- Um ataque sinaliza skip devolvendo um `*seguranca.SkipAtaqueException`
  (via `seguranca.NovoSkip`).

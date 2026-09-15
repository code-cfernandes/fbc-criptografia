package ataques

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesLinearidadeChecksum configura o AtaqueLinearidadeChecksum.
type OpcoesLinearidadeChecksum struct {
	AmostrasLinearidade int
	AmostrasDiferencial int
	TamanhoEntrada      int
}

// AtaqueLinearidadeChecksum procura linearidade no checksum, que seria fatal
// para um MAC: cs(a) XOR cs(b) == cs(a XOR b), e diferenciais de alta
// probabilidade para um delta fixo.
type AtaqueLinearidadeChecksum struct {
	amostrasLinearidade int
	amostrasDiferencial int
	tamanhoEntrada      int
}

// NovoAtaqueLinearidadeChecksum cria o ataque. Sem argumento, usa
// amostrasLinearidade = 5000, amostrasDiferencial = 500 e tamanhoEntrada = 32.
func NovoAtaqueLinearidadeChecksum(opcoes ...OpcoesLinearidadeChecksum) *AtaqueLinearidadeChecksum {
	o := OpcoesLinearidadeChecksum{AmostrasLinearidade: 5000, AmostrasDiferencial: 500, TamanhoEntrada: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueLinearidadeChecksum{
		amostrasLinearidade: o.AmostrasLinearidade,
		amostrasDiferencial: o.AmostrasDiferencial,
		tamanhoEntrada:      o.TamanhoEntrada,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueLinearidadeChecksum) Nome() string {
	return "Linearidade e diferenciais do checksum"
}

// Executar roda o ataque.
func (a *AtaqueLinearidadeChecksum) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveMac := []byte(strings.Repeat("M", 32))

	relacoesLineares := 0
	for i := 0; i < a.amostrasLinearidade; i++ {
		msgA := seguranca.RandomBytes(a.tamanhoEntrada)
		msgB := seguranca.RandomBytes(a.tamanhoEntrada)

		lhs := a.xorBytes(alvo.ChecksumBruto(msgA, chaveMac), alvo.ChecksumBruto(msgB, chaveMac))
		rhs := alvo.ChecksumBruto(a.xorBytes(msgA, msgB), chaveMac)
		if bytes.Equal(lhs, rhs) {
			relacoesLineares++
		}
	}

	maxRepeticoesDiferencial := 0
	for d := 0; d < 5; d++ {
		delta := seguranca.RandomBytes(a.tamanhoEntrada)
		vistos := map[string]int{}
		for i := 0; i < a.amostrasDiferencial; i++ {
			msg := seguranca.RandomBytes(a.tamanhoEntrada)
			dif := a.xorBytes(
				alvo.ChecksumBruto(a.xorBytes(msg, delta), chaveMac),
				alvo.ChecksumBruto(msg, chaveMac),
			)
			vistos[hex.EncodeToString(dif)]++
		}
		maxVistos := 0
		for _, c := range vistos {
			if c > maxVistos {
				maxVistos = c
			}
		}
		if maxVistos > maxRepeticoesDiferencial {
			maxRepeticoesDiferencial = maxVistos
		}
	}

	vulneravel := relacoesLineares > 0 || maxRepeticoesDiferencial > 1
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevCritica
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"%d/%d relações lineares; maior repetição de diferencial=%d (esperado 1)",
			relacoesLineares, a.amostrasLinearidade, maxRepeticoesDiferencial,
		),
		Dados: map[string]any{
			"relacoes_lineares":          relacoesLineares,
			"max_repeticoes_diferencial": maxRepeticoesDiferencial,
		},
	}, nil
}

// xorBytes faz XOR byte a byte de dois buffers.
func (a *AtaqueLinearidadeChecksum) xorBytes(a2, b []byte) []byte {
	n := min(len(a2), len(b))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a2[i] ^ b[i]
	}
	return out
}

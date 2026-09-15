package ataques

import (
	"fmt"
	"os"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueValidacaoChave verifica que a chave tem exatamente 32 bytes: tamanhos
// inválidos devem ser rejeitados e uma chave válida deve funcionar.
type AtaqueValidacaoChave struct {
	tamanhos []int
}

// NovoAtaqueValidacaoChave cria o ataque. Sem argumento, usa
// [0, 1, 16, 31, 33, 64].
func NovoAtaqueValidacaoChave(tamanhos ...[]int) *AtaqueValidacaoChave {
	t := []int{0, 1, 16, 31, 33, 64}
	if len(tamanhos) > 0 {
		t = tamanhos[0]
	}
	return &AtaqueValidacaoChave{tamanhos: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueValidacaoChave) Nome() string {
	return "Validação do tamanho da chave"
}

// Executar roda o ataque.
func (a *AtaqueValidacaoChave) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveOriginal := alvo.ChaveDeTeste()
	defer os.Setenv("FBC_KEY", chaveOriginal)

	aceitasIndevidamente := []int{}
	validaRejeitada := false

	for _, length := range a.tamanhos {
		seguranca.NovoCriptografiaAlvo(strings.Repeat("K", length))
		if _, err := alvo.Encrypt([]byte("x")); err == nil {
			aceitasIndevidamente = append(aceitasIndevidamente, length)
		}
	}

	seguranca.NovoCriptografiaAlvo(strings.Repeat("K", 32))
	if _, err := alvo.Encrypt([]byte("x")); err != nil {
		validaRejeitada = true
	}

	vulneravel := len(aceitasIndevidamente) > 0 || validaRejeitada

	if vulneravel {
		detalhes := []string{}
		if len(aceitasIndevidamente) > 0 {
			partes := make([]string, len(aceitasIndevidamente))
			for i, v := range aceitasIndevidamente {
				partes[i] = fmt.Sprint(v)
			}
			detalhes = append(detalhes, "chaves de tamanho inválido aceitas: "+strings.Join(partes, ", "))
		}
		if validaRejeitada {
			detalhes = append(detalhes, "chave válida de 32 bytes foi rejeitada")
		}
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes:   strings.Join(detalhes, "; "),
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   "Tamanhos inválidos rejeitados e chave de 32 bytes aceita",
	}, nil
}

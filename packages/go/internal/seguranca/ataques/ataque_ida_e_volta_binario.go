package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueIdaEVoltaBinario é a versão binária do AtaqueIdaEVolta: usa todos os
// 256 valores de byte, NUL e sequências aleatórias de vários tamanhos. Erros de
// manipulação de string (trim, encoding, truncamento em NUL) só aparecem com
// bytes arbitrários.
type AtaqueIdaEVoltaBinario struct {
	tamanhoMaximo int
}

// NovoAtaqueIdaEVoltaBinario cria o ataque. Sem argumento, usa
// tamanhoMaximo = 256.
func NovoAtaqueIdaEVoltaBinario(tamanhoMaximo ...int) *AtaqueIdaEVoltaBinario {
	t := 256
	if len(tamanhoMaximo) > 0 {
		t = tamanhoMaximo[0]
	}
	return &AtaqueIdaEVoltaBinario{tamanhoMaximo: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueIdaEVoltaBinario) Nome() string {
	return "Ida-e-volta com dados binários (inclui NUL)"
}

// Executar roda o ataque.
func (a *AtaqueIdaEVoltaBinario) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	falhas := []string{}

	for length := 0; length <= a.tamanhoMaximo; length++ {
		texto := []byte{}
		if length > 0 {
			texto = seguranca.RandomBytes(length)
		}
		token, err := alvo.Encrypt(texto)
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d (erro: %s)", length, err.Error()))
			continue
		}
		decifrado, err := alvo.Decrypt(token)
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d (erro: %s)", length, err.Error()))
			continue
		}
		if decifrado != string(texto) {
			falhas = append(falhas, fmt.Sprintf("%d", length))
		}
	}

	todos := make([]byte, 256)
	for i := 0; i < 256; i++ {
		todos[i] = byte(i)
	}
	tokenTodos, err := alvo.Encrypt(todos)
	if err != nil {
		falhas = append(falhas, "todos os 256 valores de byte")
	} else if decifrado, err := alvo.Decrypt(tokenTodos); err != nil || decifrado != string(todos) {
		falhas = append(falhas, "todos os 256 valores de byte")
	}

	if len(falhas) > 0 {
		limite := min(10, len(falhas))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   "Falhou em " + fmt.Sprint(len(falhas)) + " caso(s): " + strings.Join(falhas[:limite], ", "),
			Dados:      map[string]any{"falhas": falhas},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todos os tamanhos 0..%d e os 256 valores de byte preservados", a.tamanhoMaximo),
	}, nil
}

package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueIdaEVolta é a checagem de sanidade básica: encrypt seguido de decrypt
// precisa devolver o texto original, em qualquer tamanho.
type AtaqueIdaEVolta struct {
	tamanhoMaximo int
}

// NovoAtaqueIdaEVolta cria o ataque. Sem argumento, usa tamanhoMaximo = 130.
func NovoAtaqueIdaEVolta(tamanhoMaximo ...int) *AtaqueIdaEVolta {
	t := 130
	if len(tamanhoMaximo) > 0 {
		t = tamanhoMaximo[0]
	}
	return &AtaqueIdaEVolta{tamanhoMaximo: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueIdaEVolta) Nome() string {
	return "Ida-e-volta (round trip)"
}

// Executar roda o ataque.
func (a *AtaqueIdaEVolta) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	falhas := []string{}

	for length := 0; length <= a.tamanhoMaximo; length++ {
		texto := strings.Repeat("Q", length)
		token, err := alvo.Encrypt([]byte(texto))
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d (erro: %s)", length, err.Error()))
			continue
		}
		decifrado, err := alvo.Decrypt(token)
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d (erro: %s)", length, err.Error()))
			continue
		}
		if decifrado != texto {
			falhas = append(falhas, fmt.Sprintf("%d", length))
		}
	}

	if len(falhas) > 0 {
		limite := min(10, len(falhas))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   "Falhou em " + fmt.Sprint(len(falhas)) + " tamanho(s): " + strings.Join(falhas[:limite], ", "),
			Dados:      map[string]any{"falhas": falhas},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todos os %d tamanhos (0 a %d) OK", a.tamanhoMaximo+1, a.tamanhoMaximo),
	}, nil
}

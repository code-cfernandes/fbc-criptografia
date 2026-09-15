package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueBytesFixos gera vários tokens de textos diferentes e procura qualquer
// posição de byte que NUNCA muda.
type AtaqueBytesFixos struct {
	amostras int
}

// NovoAtaqueBytesFixos cria o ataque. Sem argumento, usa amostras = 30.
func NovoAtaqueBytesFixos(amostras ...int) *AtaqueBytesFixos {
	n := 30
	if len(amostras) > 0 {
		n = amostras[0]
	}
	return &AtaqueBytesFixos{amostras: n}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueBytesFixos) Nome() string {
	return "Bytes fixos entre tokens"
}

// Executar roda o ataque.
func (a *AtaqueBytesFixos) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	decodificados := [][]byte{}

	for i := 0; i < a.amostras; i++ {
		texto := fmt.Sprintf("TEXTO_VARIADO_%d", i) +
			strings.Repeat(string(rune('A'+(i%26))), i%10)
		token, err := alvo.Encrypt([]byte(texto))
		if err != nil {
			continue
		}
		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		decodificados = append(decodificados, decodificado)
	}

	if len(decodificados) == 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: false,
			Severidade: seguranca.SevInfo,
			Detalhes:   "Nenhum token pôde ser analisado",
		}, nil
	}

	tamanhoMinimo := len(decodificados[0])
	for _, d := range decodificados {
		if len(d) < tamanhoMinimo {
			tamanhoMinimo = len(d)
		}
	}

	posicoesFixas := []int{}
	for i := 0; i < tamanhoMinimo; i++ {
		valores := map[byte]bool{}
		for _, d := range decodificados {
			valores[d[i]] = true
		}
		if len(valores) == 1 {
			posicoesFixas = append(posicoesFixas, i)
		}
	}

	if len(posicoesFixas) > 0 {
		limite := min(10, len(posicoesFixas))
		partes := make([]string, limite)
		for i := 0; i < limite; i++ {
			partes[i] = fmt.Sprint(posicoesFixas[i])
		}
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes: fmt.Sprintf("%d posição(ões) de byte fixas em %d tokens: %s",
				len(posicoesFixas), a.amostras, strings.Join(partes, ", ")),
			Dados: map[string]any{"posicoes": posicoesFixas},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("0 de %d posições fixas em %d tokens", tamanhoMinimo, a.amostras),
	}, nil
}

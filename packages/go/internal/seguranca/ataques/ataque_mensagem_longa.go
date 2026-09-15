package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueMensagemLonga testa mensagens grandes (vários blocos de 32 bytes de
// keystream). Erros de sincronização de bloco, repetição de keystream em blocos
// distantes ou perda de bytes só aparecem em mensagens longas. Também confirma
// que o mesmo texto com IVs diferentes gera tokens diferentes.
type AtaqueMensagemLonga struct {
	tamanhos []int
}

// NovoAtaqueMensagemLonga cria o ataque. Sem argumento, usa
// tamanhos = [1000, 10000, 100000].
func NovoAtaqueMensagemLonga(tamanhos ...[]int) *AtaqueMensagemLonga {
	t := []int{1000, 10000, 100000}
	if len(tamanhos) > 0 {
		t = tamanhos[0]
	}
	return &AtaqueMensagemLonga{tamanhos: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueMensagemLonga) Nome() string {
	return "Mensagens longas (multi-bloco)"
}

// Executar roda o ataque.
func (a *AtaqueMensagemLonga) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	falhas := []string{}

	for _, t := range a.tamanhos {
		texto := seguranca.RandomBytes(t)
		token, err := alvo.Encrypt(texto)
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d bytes (erro: %s)", t, err.Error()))
			continue
		}
		decifrado, err := alvo.Decrypt(token)
		if err != nil {
			falhas = append(falhas, fmt.Sprintf("%d bytes (erro: %s)", t, err.Error()))
			continue
		}
		if decifrado != string(texto) {
			falhas = append(falhas, fmt.Sprintf("%d bytes (conteúdo diferente)", t))
		}
	}

	texto := strings.Repeat("A", 1000)
	t1, err1 := alvo.Encrypt([]byte(texto))
	t2, err2 := alvo.Encrypt([]byte(texto))
	if err1 == nil && err2 == nil && t1 == t2 {
		falhas = append(falhas, "tokens idênticos para o mesmo texto (IV não varia)")
	}

	if len(falhas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   "Falha em: " + strings.Join(falhas, "; "),
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   "Ida-e-volta OK em " + a.tamanhosComoString() + " bytes; mesmo texto gera tokens distintos",
	}, nil
}

// tamanhosComoString junta os tamanhos testados para o relatório.
func (a *AtaqueMensagemLonga) tamanhosComoString() string {
	partes := make([]string, len(a.tamanhos))
	for i, t := range a.tamanhos {
		partes[i] = fmt.Sprint(t)
	}
	return strings.Join(partes, ", ")
}

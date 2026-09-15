package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueCanonicalizacaoToken verifica se um mesmo token aceita múltiplas
// representações textuais válidas (base64url não-canônico / token smuggling).
type AtaqueCanonicalizacaoToken struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCanonicalizacaoToken) Nome() string {
	return "Canonicalização do token (base64 não-canônico)"
}

type varianteToken struct {
	nome  string
	valor string
}

// Executar roda o ataque.
func (a *AtaqueCanonicalizacaoToken) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	texto := "MENSAGEM_DE_TESTE_DE_CANONICALIZACAO"
	token, err := alvo.Encrypt([]byte(texto))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	prefixo := alvo.Prefixo()
	corpo := token[len(prefixo):]
	meio := len(corpo) / 2

	variantes := []varianteToken{}
	for _, p := range []int{0, meio, len(corpo) - 1} {
		variantes = append(variantes,
			varianteToken{nome: fmt.Sprintf("espaço na posição %d", p), valor: prefixo + corpo[:p] + " " + corpo[p:]},
			varianteToken{nome: fmt.Sprintf("newline na posição %d", p), valor: prefixo + corpo[:p] + "\n" + corpo[p:]},
			varianteToken{nome: fmt.Sprintf("tab na posição %d", p), valor: prefixo + corpo[:p] + "\t" + corpo[p:]},
		)
	}
	alfabetoPadrao := strings.ReplaceAll(strings.ReplaceAll(corpo, "-", "+"), "_", "/")
	variantes = append(variantes,
		varianteToken{nome: "alfabeto padrão (+/)", valor: prefixo + alfabetoPadrao},
		varianteToken{nome: "padding \"=\" extra", valor: prefixo + corpo + "="},
		varianteToken{nome: "caractere inválido no meio", valor: prefixo + corpo[:meio] + "!" + corpo[meio:]},
	)

	aceitas := []string{}
	for _, v := range variantes {
		if v.valor == token {
			continue
		}
		if decifrado, err := alvo.Decrypt(v.valor); err == nil && decifrado == texto {
			aceitas = append(aceitas, v.nome)
		}
	}

	if len(aceitas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevMedia,
			Detalhes: fmt.Sprintf(
				"%d variante(s) textualmente diferente(s) decifram para o mesmo texto: %s",
				len(aceitas), strings.Join(aceitas, "; "),
			),
			Dados: map[string]any{"variantes_aceitas": aceitas},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todas as %d variantes não-canônicas foram rejeitadas", len(variantes)),
	}, nil
}

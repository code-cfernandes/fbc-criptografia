package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesMac configura o AtaqueMac.
type OpcoesMac struct {
	Mensagem string
}

// AtaqueMac tenta truncar o campo de integridade, zerá-lo e forçar (força bruta
// de 1 byte) valores para ver se algum token adulterado é aceito.
type AtaqueMac struct {
	mensagem string
}

// NovoAtaqueMac cria o ataque. Sem argumento, usa
// mensagem = "mensagem para o ataque de MAC".
func NovoAtaqueMac(opcoes ...OpcoesMac) *AtaqueMac {
	o := OpcoesMac{Mensagem: "mensagem para o ataque de MAC"}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueMac{mensagem: o.Mensagem}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueMac) Nome() string {
	return "Força bruta e truncamento do MAC"
}

// Executar roda o ataque.
func (a *AtaqueMac) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	token, err := alvo.Encrypt([]byte(a.mensagem))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	decoded, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	campos := alvo.Decompor(decoded)

	montar := func(integridade []byte) string {
		return alvo.Prefixo() + alvo.Base64urlEncode(alvo.Recompor(seguranca.CamposToken{
			Integridade: integridade,
			Ciphertext:  campos.Ciphertext,
			IV:          campos.IV,
		}))
	}

	aceitos := []string{}

	// 1) integridade zerada
	if _, err := alvo.Decrypt(montar(make([]byte, len(campos.Integridade)))); err == nil {
		aceitos = append(aceitos, "integridade zerada")
	}

	// 2) integridade truncada pela metade
	if _, err := alvo.Decrypt(montar(campos.Integridade[:16])); err == nil {
		aceitos = append(aceitos, "integridade truncada (16 bytes)")
	}

	// 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
	// que reconstruiria o próprio token válido e não é uma forja)
	base := append([]byte(nil), campos.Integridade...)
	for v := 0; v < 256; v++ {
		if byte(v) == base[0] {
			continue
		}
		tentativa := append([]byte(nil), base...)
		tentativa[0] = byte(v)
		if _, err := alvo.Decrypt(montar(tentativa)); err == nil {
			aceitos = append(aceitos, fmt.Sprintf("byte 0 do MAC = %d", v))
		}
	}

	vulneravel := len(aceitos) > 0
	severidade := seguranca.SevInfo
	detalhes := "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita"
	if vulneravel {
		severidade = seguranca.SevCritica
		detalhes = fmt.Sprintf("%d variante(s) de MAC aceitas: %s", len(aceitos), strings.Join(aceitos[:min(5, len(aceitos))], "; "))
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"aceitos": aceitos},
	}, nil
}

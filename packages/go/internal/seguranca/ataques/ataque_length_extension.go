package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesLengthExtension configura o AtaqueLengthExtension.
type OpcoesLengthExtension struct {
	Mensagem string
}

// AtaqueLengthExtension verifica que truncar, estender ou deslocar bytes do
// token não produz um token aceito.
type AtaqueLengthExtension struct {
	mensagem string
}

// NovoAtaqueLengthExtension cria o ataque. Sem argumento, usa
// mensagem = "texto para o ataque de length extension".
func NovoAtaqueLengthExtension(opcoes ...OpcoesLengthExtension) *AtaqueLengthExtension {
	o := OpcoesLengthExtension{Mensagem: "texto para o ataque de length extension"}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueLengthExtension{mensagem: o.Mensagem}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueLengthExtension) Nome() string {
	return "Length extension / truncamento de token"
}

type varianteLengthExtension struct {
	nome  string
	valor string
}

// Executar roda o ataque.
func (a *AtaqueLengthExtension) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	prefixo := alvo.Prefixo()
	token, err := alvo.Encrypt([]byte(a.mensagem))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	corpo := token[len(prefixo):]
	meio := len(corpo) / 2

	variantes := []varianteLengthExtension{
		{nome: "append A", valor: prefixo + corpo + "A"},
		{nome: "append =", valor: prefixo + corpo + "="},
		{nome: "truncar 1 char", valor: prefixo + corpo[:len(corpo)-1]},
		{nome: "truncar 2 chars", valor: prefixo + corpo[:len(corpo)-2]},
		{nome: "inserir ! no meio", valor: prefixo + corpo[:meio] + "!" + corpo[meio:]},
		{nome: "prefixo extra", valor: prefixo + "A" + corpo},
	}

	// variantes que mexem nos campos decodificados
	if decoded, err := alvo.Base64urlDecode(corpo); err == nil {
		campos := alvo.Decompor(decoded)

		ctMaior := concatenar(campos.Ciphertext, []byte{0x41})
		variantes = append(variantes, varianteLengthExtension{
			nome:  "ciphertext +1 byte",
			valor: prefixo + alvo.Base64urlEncode(alvo.Recompor(seguranca.CamposToken{Integridade: campos.Integridade, Ciphertext: ctMaior, IV: campos.IV})),
		})

		ctMenorLen := len(campos.Ciphertext) - 1
		if ctMenorLen < 0 {
			ctMenorLen = 0
		}
		ctMenor := campos.Ciphertext[:ctMenorLen]
		variantes = append(variantes, varianteLengthExtension{
			nome:  "ciphertext -1 byte",
			valor: prefixo + alvo.Base64urlEncode(alvo.Recompor(seguranca.CamposToken{Integridade: campos.Integridade, Ciphertext: ctMenor, IV: campos.IV})),
		})

		ivMaior := concatenar(campos.IV, []byte{0x42})
		variantes = append(variantes, varianteLengthExtension{
			nome:  "iv +1 byte",
			valor: prefixo + alvo.Base64urlEncode(alvo.Recompor(seguranca.CamposToken{Integridade: campos.Integridade, Ciphertext: campos.Ciphertext, IV: ivMaior})),
		})
	}

	aceitas := []string{}
	for _, v := range variantes {
		if v.valor == token {
			continue
		}
		if _, err := alvo.Decrypt(v.valor); err == nil {
			aceitas = append(aceitas, v.nome)
		}
	}

	vulneravel := len(aceitas) > 0
	severidade := seguranca.SevInfo
	detalhes := fmt.Sprintf("Todas as %d variantes de truncamento/extensão foram rejeitadas", len(variantes))
	if vulneravel {
		severidade = seguranca.SevCritica
		detalhes = fmt.Sprintf("%d variante(s) aceita(s): %s", len(aceitas), strings.Join(aceitas, "; "))
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"aceitas": aceitas},
	}, nil
}

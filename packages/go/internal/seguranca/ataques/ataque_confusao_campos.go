package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// AtaqueConfusaoCampos testa se rearranjos/deslocamentos dos campos do token
// (integridade[32] . ciphertext[n] . iv[16]) são aceitos.
type AtaqueConfusaoCampos struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueConfusaoCampos) Nome() string {
	return "Confusão de campos do token (reordenação/deslocamento)"
}

type varianteCampos struct {
	nome  string
	bruto []byte
}

// concatenar junta vários buffers.
func concatenar(partes ...[]byte) []byte {
	total := 0
	for _, p := range partes {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range partes {
		out = append(out, p...)
	}
	return out
}

// Executar roda o ataque.
func (a *AtaqueConfusaoCampos) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	texto := "MENSAGEM_PARA_TESTE_DE_CAMPOS"
	token, err := alvo.Encrypt([]byte(texto))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	prefixo := alvo.Prefixo()
	decodificado, err := alvo.Base64urlDecode(token[len(prefixo):])
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	campos := alvo.Decompor(decodificado)

	integridade := campos.Integridade
	ciphertext := campos.Ciphertext
	iv := campos.IV

	ivInvertido := append([]byte(nil), iv...)
	for i, j := 0, len(ivInvertido)-1; i < j; i, j = i+1, j-1 {
		ivInvertido[i], ivInvertido[j] = ivInvertido[j], ivInvertido[i]
	}

	variantes := []varianteCampos{
		{nome: "iv no início", bruto: concatenar(iv, integridade, ciphertext)},
		{nome: "ciphertext antes da integridade", bruto: concatenar(ciphertext, integridade, iv)},
		{nome: "iv duplicado no fim", bruto: concatenar(integridade, ciphertext, iv, iv)},
		{nome: "integridade encurtada", bruto: concatenar(integridade[1:], ciphertext, iv)},
		{nome: "byte extra no início", bruto: concatenar([]byte("X"), integridade, ciphertext, iv)},
		{nome: "byte extra entre integridade e ciphertext", bruto: concatenar(integridade, []byte("X"), ciphertext, iv)},
		{nome: "byte extra antes do iv", bruto: concatenar(integridade, ciphertext, []byte("X"), iv)},
		{nome: "iv rotacionado", bruto: concatenar(integridade, ciphertext, ivInvertido)},
		{
			nome:  "iv e último byte do ciphertext trocados",
			bruto: concatenar(integridade, ciphertext[:len(ciphertext)-1], iv, ciphertext[len(ciphertext)-1:]),
		},
	}

	aceitas := []string{}
	for _, v := range variantes {
		tokenVariante := prefixo + alvo.Base64urlEncode(v.bruto)
		if r, err := alvo.Decrypt(tokenVariante); err == nil {
			aceitas = append(aceitas, fmt.Sprintf("%s -> aceito (retornou %d bytes)", v.nome, len([]byte(r))))
		}
	}

	if len(aceitas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   fmt.Sprintf("%d rearranjo(s) de campo foram aceitos", len(aceitas)),
			Dados:      map[string]any{"exemplos": aceitas},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todos os %d rearranjos de campo foram rejeitados", len(variantes)),
	}, nil
}

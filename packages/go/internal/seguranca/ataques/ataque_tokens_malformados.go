package ataques

import (
	"encoding/hex"
	"fmt"

	"criptografia/internal/seguranca"
)

// AtaqueTokensMalformados faz fuzzing do parser: qualquer entrada que não seja
// um token íntegro e bem formado deve ser rejeitada com erro.
type AtaqueTokensMalformados struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueTokensMalformados) Nome() string {
	return "Tokens malformados (fuzzing de entrada)"
}

type casoTokenMalformado struct {
	nome  string
	valor string
}

// Executar roda o ataque.
func (a *AtaqueTokensMalformados) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	token, err := alvo.Encrypt([]byte("MENSAGEM_VALIDA_PARA_TESTE"))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	prefixo := alvo.Prefixo()
	corpo := token[len(prefixo):]

	casos := []casoTokenMalformado{
		{nome: "vazio", valor: ""},
		{nome: "só prefixo", valor: prefixo},
		{nome: "prefixo errado", valor: "XXX" + corpo},
		{nome: "base64 inválido", valor: prefixo + "!!!@@@###"},
		{nome: "bytes extras no fim", valor: token + "AAAA"},
		{nome: "bytes extras no início", valor: "AAAA" + token},
	}
	for length := 1; length < len(token); length++ {
		casos = append(casos, casoTokenMalformado{nome: fmt.Sprintf("truncado em %d", length), valor: token[:length]})
	}
	for i := 0; i < 20; i++ {
		casos = append(casos, casoTokenMalformado{
			nome:  fmt.Sprintf("lixo aleatório %d", i),
			valor: prefixo + hex.EncodeToString(seguranca.RandomBytes(16)),
		})
	}

	aceitos := []string{}
	for _, c := range casos {
		r, err := alvo.Decrypt(c.valor)
		if err == nil {
			aceitos = append(aceitos, fmt.Sprintf("%s -> aceito (retornou %d bytes)", c.nome, len([]byte(r))))
		}
	}

	if len(aceitos) > 0 {
		limite := min(10, len(aceitos))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   fmt.Sprintf("%d entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas", len(aceitos)),
			Dados:      map[string]any{"exemplos": aceitos[:limite]},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todas as %d entradas malformadas foram rejeitadas", len(casos)),
	}, nil
}

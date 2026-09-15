package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueAdulteracao verifica se um bit flipado em QUALQUER campo do token
// (ciphertext, iv ou integridade) ainda decifra "com sucesso".
type AtaqueAdulteracao struct {
	tentativas int
}

// NovoAtaqueAdulteracao cria o ataque. Sem argumento, usa tentativas = 500.
func NovoAtaqueAdulteracao(tentativas ...int) *AtaqueAdulteracao {
	t := 500
	if len(tentativas) > 0 {
		t = tentativas[0]
	}
	return &AtaqueAdulteracao{tentativas: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAdulteracao) Nome() string {
	return "Adulteração de bits (integridade)"
}

// Executar roda o ataque.
func (a *AtaqueAdulteracao) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	aceitosIndevidamente := []string{}

	for t := 0; t < a.tentativas; t++ {
		texto := fmt.Sprintf("MSG_%d", t) + strings.Repeat("X", seguranca.RandomInt(0, 50))
		token, err := alvo.Encrypt([]byte(texto))
		if err != nil {
			continue
		}

		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		campos := alvo.Decompor(decodificado)

		nomeCampo := seguranca.RandomInt(0, 2)
		var valor []byte
		switch nomeCampo {
		case 0:
			valor = append([]byte(nil), campos.Integridade...)
		case 1:
			valor = append([]byte(nil), campos.Ciphertext...)
		case 2:
			valor = append([]byte(nil), campos.IV...)
		}
		if len(valor) == 0 {
			continue
		}

		pos := seguranca.RandomInt(0, len(valor)-1)
		valor[pos] ^= byte(1 << seguranca.RandomInt(0, 7))

		switch nomeCampo {
		case 0:
			campos.Integridade = valor
		case 1:
			campos.Ciphertext = valor
		case 2:
			campos.IV = valor
		}

		tokenAdulterado := alvo.Prefixo() + alvo.Base64urlEncode(alvo.Recompor(campos))

		if resultado, err := alvo.Decrypt(tokenAdulterado); err == nil {
			aceitosIndevidamente = append(
				aceitosIndevidamente,
				fmt.Sprintf("campo=%d, texto original=%s, resultado aceito=%s", nomeCampo, texto, resultado),
			)
		}
	}

	if len(aceitosIndevidamente) > 0 {
		limite := min(5, len(aceitosIndevidamente))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   fmt.Sprintf("%d de %d tokens adulterados foram ACEITOS", len(aceitosIndevidamente), a.tentativas),
			Dados:      map[string]any{"exemplos": aceitosIndevidamente[:limite]},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todas as %d adulterações foram rejeitadas", a.tentativas),
	}, nil
}

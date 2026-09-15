package ataques

import (
	"encoding/hex"
	"fmt"
	"os"

	"criptografia/internal/seguranca"
)

// AtaqueChaveErrada garante que um token só decifra com a chave correta.
type AtaqueChaveErrada struct {
	tentativas int
}

// NovoAtaqueChaveErrada cria o ataque. Sem argumento, usa tentativas = 30.
func NovoAtaqueChaveErrada(tentativas ...int) *AtaqueChaveErrada {
	t := 30
	if len(tentativas) > 0 {
		t = tentativas[0]
	}
	return &AtaqueChaveErrada{tentativas: t}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueChaveErrada) Nome() string {
	return "Rejeição de chave incorreta"
}

// Executar roda o ataque.
func (a *AtaqueChaveErrada) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveOriginal := alvo.ChaveDeTeste()
	defer os.Setenv("FBC_KEY", chaveOriginal)

	tokens := []string{}
	for i := 0; i < a.tentativas; i++ {
		token, err := alvo.Encrypt([]byte(fmt.Sprintf("MENSAGEM_SECRETA_%d", i)))
		if err != nil {
			continue
		}
		tokens = append(tokens, token)
	}

	aceitos := []string{}
	for i, token := range tokens {
		seguranca.NovoCriptografiaAlvo(hex.EncodeToString(seguranca.RandomBytes(16)))
		if resultado, err := alvo.Decrypt(token); err == nil {
			aceitos = append(aceitos, fmt.Sprintf("tentativa %d aceitou (retornou %s)", i, resultado))
		}
	}

	if len(aceitos) > 0 {
		limite := min(5, len(aceitos))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   fmt.Sprintf("%d de %d tokens foram aceitos com a chave errada", len(aceitos), a.tentativas),
			Dados:      map[string]any{"exemplos": aceitos[:limite]},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Nenhum dos %d tokens foi aceito com chave incorreta", a.tentativas),
	}, nil
}

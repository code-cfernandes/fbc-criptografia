package ataques

import (
	"bytes"
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesSeparacaoChaveIV configura o AtaqueSeparacaoChaveIV.
type OpcoesSeparacaoChaveIV struct {
	Tentativas   int
	TamanhoBloco int
}

// AtaqueSeparacaoChaveIV testa se o keystream depende de key e iv apenas pela
// combinação key XOR iv: keystream(key, iv) == keystream(key^d, iv^d).
type AtaqueSeparacaoChaveIV struct {
	tentativas   int
	tamanhoBloco int
}

// NovoAtaqueSeparacaoChaveIV cria o ataque. Sem argumento, usa tentativas = 50
// e tamanhoBloco = 32.
func NovoAtaqueSeparacaoChaveIV(opcoes ...OpcoesSeparacaoChaveIV) *AtaqueSeparacaoChaveIV {
	o := OpcoesSeparacaoChaveIV{Tentativas: 50, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueSeparacaoChaveIV{tentativas: o.Tentativas, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueSeparacaoChaveIV) Nome() string {
	return "Separação chave/IV (invariância a key XOR iv)"
}

// Executar roda o ataque.
func (a *AtaqueSeparacaoChaveIV) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamChave := len(alvo.ChaveDeTeste())
	tamIv := alvo.TamanhoIv()

	confirmacoes := 0
	for t := 0; t < a.tentativas; t++ {
		chave := seguranca.RandomBytes(tamChave)
		iv := seguranca.RandomBytes(tamIv)
		d := seguranca.RandomBytes(tamIv)

		chave2 := make([]byte, tamChave)
		for p := 0; p < tamChave; p++ {
			chave2[p] = chave[p] ^ d[p%tamIv]
		}
		iv2 := make([]byte, tamIv)
		for p := 0; p < tamIv; p++ {
			iv2[p] = iv[p] ^ d[p]
		}

		ks1 := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanhoBloco)
		ks2 := alvo.GerarKeystreamBruto(chave2, iv2, "enc", a.tamanhoBloco)

		if bytes.Equal(ks1, ks2) {
			confirmacoes++
		}
	}

	invariante := confirmacoes == a.tentativas

	severidade := seguranca.SevInfo
	detalhes := fmt.Sprintf(
		"Invariância não se confirmou (%d/%d); key e iv entram de forma independente.",
		confirmacoes, a.tentativas,
	)
	if invariante {
		severidade = seguranca.SevMedia
		detalhes = fmt.Sprintf(
			"Confirmado em %d/%d: keystream(key,iv) == keystream(key^d, iv^d). "+
				"O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule.",
			a.tentativas, a.tentativas,
		)
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: invariante,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"confirmacoes": confirmacoes, "tentativas": a.tentativas},
	}, nil
}

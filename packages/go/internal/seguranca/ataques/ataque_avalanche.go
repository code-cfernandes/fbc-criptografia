package ataques

import (
	"fmt"
	"sort"

	"criptografia/internal/seguranca"
)

// OpcoesAvalanche configura o AtaqueAvalanche.
type OpcoesAvalanche struct {
	Amostras       int
	TamanhoBloco   int
	LimiteMedia    float64
	LimitePiorCaso float64
}

// AtaqueAvalanche mede a difusão de 1 bit do IV no keystream gerado.
type AtaqueAvalanche struct {
	amostras       int
	tamanhoBloco   int
	limiteMedia    float64
	limitePiorCaso float64
}

// NovoAtaqueAvalanche cria o ataque. Sem argumento, usa amostras = 3000,
// tamanhoBloco = 32, limiteMedia = 0.45 e limitePiorCaso = 0.3.
func NovoAtaqueAvalanche(opcoes ...OpcoesAvalanche) *AtaqueAvalanche {
	o := OpcoesAvalanche{Amostras: 3000, TamanhoBloco: 32, LimiteMedia: 0.45, LimitePiorCaso: 0.3}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueAvalanche{
		amostras:       o.Amostras,
		tamanhoBloco:   o.TamanhoBloco,
		limiteMedia:    o.LimiteMedia,
		limitePiorCaso: o.LimitePiorCaso,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAvalanche) Nome() string {
	return "Efeito avalanche"
}

// Executar roda o ataque.
func (a *AtaqueAvalanche) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	tamanhoIv := alvo.TamanhoIv()

	valores := make([]float64, 0, a.amostras)
	for t := 0; t < a.amostras; t++ {
		iv1 := seguranca.RandomBytes(tamanhoIv)
		iv2 := append([]byte(nil), iv1...)
		pos := seguranca.RandomInt(0, tamanhoIv-1)
		iv2[pos] ^= byte(1 << seguranca.RandomInt(0, 7))

		ks1 := alvo.GerarKeystreamBruto(chave, iv1, "enc", a.tamanhoBloco)
		ks2 := alvo.GerarKeystreamBruto(chave, iv2, "enc", a.tamanhoBloco)

		valores = append(valores, float64(seguranca.BitsDiferentes(ks1, ks2))/float64(a.tamanhoBloco*8))
	}

	sort.Float64s(valores)
	n := len(valores)
	media := 0.0
	for _, v := range valores {
		media += v
	}
	media /= float64(n)
	piorCaso := valores[0]

	vulneravel := media < a.limiteMedia || piorCaso < a.limitePiorCaso
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	percentil := valores[int(float64(n)*0.01)]

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"média=%.1f%%, pior caso=%.1f%%, percentil 1%%=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)",
			media*100, piorCaso*100, percentil*100, a.limiteMedia*100, a.limitePiorCaso*100,
		),
		Dados: map[string]any{"media": media, "pior_caso": piorCaso},
	}, nil
}

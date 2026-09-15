package ataques

import (
	"fmt"
	"sort"

	"criptografia/internal/seguranca"
)

// OpcoesAvalancheChave configura o AtaqueAvalancheChave.
type OpcoesAvalancheChave struct {
	Amostras       int
	TamanhoBloco   int
	LimiteMedia    float64
	LimitePiorCaso float64
}

// AtaqueAvalancheChave mede a difusão de 1 bit da CHAVE no keystream gerado.
type AtaqueAvalancheChave struct {
	amostras       int
	tamanhoBloco   int
	limiteMedia    float64
	limitePiorCaso float64
}

// NovoAtaqueAvalancheChave cria o ataque. Sem argumento, usa amostras = 3000,
// tamanhoBloco = 32, limiteMedia = 0.45 e limitePiorCaso = 0.3.
func NovoAtaqueAvalancheChave(opcoes ...OpcoesAvalancheChave) *AtaqueAvalancheChave {
	o := OpcoesAvalancheChave{Amostras: 3000, TamanhoBloco: 32, LimiteMedia: 0.45, LimitePiorCaso: 0.3}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueAvalancheChave{
		amostras:       o.Amostras,
		tamanhoBloco:   o.TamanhoBloco,
		limiteMedia:    o.LimiteMedia,
		limitePiorCaso: o.LimitePiorCaso,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAvalancheChave) Nome() string {
	return "Efeito avalanche da chave"
}

// Executar roda o ataque.
func (a *AtaqueAvalancheChave) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveBase := []byte(alvo.ChaveDeTeste())
	lenChave := len(chaveBase)
	iv := seguranca.RandomBytes(alvo.TamanhoIv())

	valores := make([]float64, 0, a.amostras)
	for t := 0; t < a.amostras; t++ {
		chave := append([]byte(nil), chaveBase...)
		pos := seguranca.RandomInt(0, lenChave-1)
		chave[pos] ^= byte(1 << seguranca.RandomInt(0, 7))

		ks1 := alvo.GerarKeystreamBruto(chaveBase, iv, "enc", a.tamanhoBloco)
		ks2 := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanhoBloco)

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

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"média=%.1f%%, pior caso=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)",
			media*100, piorCaso*100, a.limiteMedia*100, a.limitePiorCaso*100,
		),
		Dados: map[string]any{"media": media, "pior_caso": piorCaso},
	}, nil
}

package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesChaveRelacionada configura o AtaqueChaveRelacionada.
type OpcoesChaveRelacionada struct {
	TamanhoBloco int
	IvPorDelta   int
	LimiteMedia  float64
	LimitePior   float64
}

// AtaqueChaveRelacionada: chaves que diferem por um padrão fixo (1 bit, 0xFF,
// complemento) não devem gerar keystreams correlacionados.
type AtaqueChaveRelacionada struct {
	tamanhoBloco int
	ivPorDelta   int
	limiteMedia  float64
	limitePior   float64
}

// NovoAtaqueChaveRelacionada cria o ataque. Sem argumento, usa
// tamanhoBloco = 32, ivPorDelta = 3, limiteMedia = 0.45 e limitePior = 0.3.
func NovoAtaqueChaveRelacionada(opcoes ...OpcoesChaveRelacionada) *AtaqueChaveRelacionada {
	o := OpcoesChaveRelacionada{TamanhoBloco: 32, IvPorDelta: 3, LimiteMedia: 0.45, LimitePior: 0.3}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueChaveRelacionada{
		tamanhoBloco: o.TamanhoBloco,
		ivPorDelta:   o.IvPorDelta,
		limiteMedia:  o.LimiteMedia,
		limitePior:   o.LimitePior,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueChaveRelacionada) Nome() string {
	return "Chave relacionada (related-key)"
}

// Executar roda o ataque.
func (a *AtaqueChaveRelacionada) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveBase := []byte(alvo.ChaveDeTeste())
	length := len(chaveBase)

	deltas := make([][]byte, 0, 2*length+1)
	for i := 0; i < length; i++ {
		d := make([]byte, length)
		d[i] = 0x01
		deltas = append(deltas, d)
	}
	for i := 0; i < length; i++ {
		d := make([]byte, length)
		d[i] = 0xff
		deltas = append(deltas, d)
	}
	complemento := make([]byte, length)
	for i := 0; i < length; i++ {
		complemento[i] = chaveBase[i] ^ 0xff
	}
	deltas = append(deltas, complemento)

	valores := make([]float64, 0)
	totalBits := a.tamanhoBloco * 8

	for _, delta := range deltas {
		chaveRelacionada := make([]byte, length)
		for i := 0; i < length; i++ {
			chaveRelacionada[i] = chaveBase[i] ^ delta[i]
		}
		for s := 0; s < a.ivPorDelta; s++ {
			iv := seguranca.RandomBytes(alvo.TamanhoIv())
			ks1 := alvo.GerarKeystreamBruto(chaveBase, iv, "enc", a.tamanhoBloco)
			ks2 := alvo.GerarKeystreamBruto(chaveRelacionada, iv, "enc", a.tamanhoBloco)
			valores = append(valores, float64(seguranca.BitsDiferentes(ks1, ks2))/float64(totalBits))
		}
	}

	media := 0.0
	for _, v := range valores {
		media += v
	}
	media /= float64(len(valores))
	pior := valores[0]
	for _, v := range valores {
		if v < pior {
			pior = v
		}
	}

	vulneravel := media < a.limiteMedia || pior < a.limitePior
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"média=%.1f%%, pior=%.1f%% em %d pares (limites: média>=%.0f%%, pior>=%.0f%%)",
			media*100, pior*100, len(valores), a.limiteMedia*100, a.limitePior*100,
		),
		Dados: map[string]any{"media": media, "pior": pior},
	}, nil
}

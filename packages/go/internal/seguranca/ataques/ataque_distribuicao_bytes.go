package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesDistribuicaoBytes configura o AtaqueDistribuicaoBytes.
type OpcoesDistribuicaoBytes struct {
	AmostrasDeBlocos int
	TamanhoBloco     int
}

// AtaqueDistribuicaoBytes verifica se os bytes do keystream estão
// uniformemente distribuídos entre 0-255 (qui-quadrado).
type AtaqueDistribuicaoBytes struct {
	amostrasDeBlocos int
	tamanhoBloco     int
}

// NovoAtaqueDistribuicaoBytes cria o ataque. Sem argumento, usa
// amostrasDeBlocos = 500 e tamanhoBloco = 32.
func NovoAtaqueDistribuicaoBytes(opcoes ...OpcoesDistribuicaoBytes) *AtaqueDistribuicaoBytes {
	o := OpcoesDistribuicaoBytes{AmostrasDeBlocos: 500, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueDistribuicaoBytes{amostrasDeBlocos: o.AmostrasDeBlocos, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueDistribuicaoBytes) Nome() string {
	return "Distribuição de bytes (qui-quadrado)"
}

// Executar roda o ataque.
func (a *AtaqueDistribuicaoBytes) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())

	contagem := make([]int, 256)
	total := 0
	for i := 0; i < a.amostrasDeBlocos; i++ {
		ks := alvo.GerarKeystreamBruto(chave, seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanhoBloco)
		for j := 0; j < len(ks); j++ {
			contagem[ks[j]]++
			total++
		}
	}

	esperado := float64(total) / 256
	qui2 := 0.0
	for _, c := range contagem {
		diff := float64(c) - esperado
		qui2 += (diff * diff) / esperado
	}

	vulneravel := qui2 > 330
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevMedia
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"qui-quadrado=%.1f sobre %d bytes (255 graus de liberdade; >330 é suspeito)",
			qui2, total,
		),
		Dados: map[string]any{"qui2": qui2},
	}, nil
}

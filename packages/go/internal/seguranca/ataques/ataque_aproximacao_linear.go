package ataques

import (
	"fmt"
	"math"

	"criptografia/internal/seguranca"
)

// OpcoesAproximacaoLinear configura o AtaqueAproximacaoLinear.
type OpcoesAproximacaoLinear struct {
	Amostras     int
	TamanhoBloco int
	LimiteBias   float64
}

// AtaqueAproximacaoLinear (criptoanálise de Matsui) procura correlação entre
// bits de entrada (IV) e bits de saída do keystream.
type AtaqueAproximacaoLinear struct {
	amostras     int
	tamanhoBloco int
	limiteBias   float64
}

// NovoAtaqueAproximacaoLinear cria o ataque. Sem argumento, usa amostras = 200,
// tamanhoBloco = 32 e limiteBias = 0.3.
func NovoAtaqueAproximacaoLinear(opcoes ...OpcoesAproximacaoLinear) *AtaqueAproximacaoLinear {
	o := OpcoesAproximacaoLinear{Amostras: 200, TamanhoBloco: 32, LimiteBias: 0.3}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueAproximacaoLinear{amostras: o.Amostras, tamanhoBloco: o.TamanhoBloco, limiteBias: o.LimiteBias}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAproximacaoLinear) Nome() string {
	return "Aproximação linear (viés de Walsh)"
}

// Executar roda o ataque.
func (a *AtaqueAproximacaoLinear) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamIv := alvo.TamanhoIv()
	bitsEntrada := tamIv * 8
	bitsSaida := a.tamanhoBloco * 8

	entradas := make([][]byte, a.amostras)
	saidas := make([][]byte, a.amostras)

	for s := 0; s < a.amostras; s++ {
		chave := seguranca.RandomBytes(len(alvo.ChaveDeTeste()))
		iv := seguranca.RandomBytes(tamIv)
		ks := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanhoBloco)

		inBits := make([]byte, bitsEntrada)
		for j := 0; j < bitsEntrada; j++ {
			inBits[j] = (iv[j>>3] >> (7 - (j & 7))) & 1
		}
		outBits := make([]byte, bitsSaida)
		for j := 0; j < bitsSaida; j++ {
			outBits[j] = (ks[j>>3] >> (7 - (j & 7))) & 1
		}
		entradas[s] = inBits
		saidas[s] = outBits
	}

	maiorBias := 0.0
	par := [2]int{-1, -1}
	for i := 0; i < bitsEntrada; i++ {
		for j := 0; j < bitsSaida; j++ {
			iguais := 0
			for s := 0; s < a.amostras; s++ {
				if entradas[s][i] == saidas[s][j] {
					iguais++
				}
			}
			bias := math.Abs(float64(iguais)/float64(a.amostras) - 0.5)
			if bias > maiorBias {
				maiorBias = bias
				par = [2]int{i, j}
			}
		}
	}

	vulneravel := maiorBias > a.limiteBias
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"maior viés |p-0.5|=%.4f na aproximação IV[bit %d] -> saída[bit %d] (limite %v); %d amostras",
			maiorBias, par[0], par[1], a.limiteBias, a.amostras,
		),
		Dados: map[string]any{"maior_bias": maiorBias, "par": par},
	}, nil
}

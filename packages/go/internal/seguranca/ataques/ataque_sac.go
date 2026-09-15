package ataques

import (
	"fmt"
	"math"

	"criptografia/internal/seguranca"
)

// OpcoesSAC configura o AtaqueSAC.
type OpcoesSAC struct {
	TamanhoBloco int
	Amostras     int
	Tolerancia   float64
}

// AtaqueSAC (Strict Avalanche Criterion): para cada bit do IV, ao virá-lo cada
// bit de saída deve mudar com probabilidade ~0.5. Mede o pior bit de saída.
type AtaqueSAC struct {
	tamanhoBloco int
	amostras     int
	tolerancia   float64
}

// NovoAtaqueSAC cria o ataque. Sem argumento, usa tamanhoBloco = 32,
// amostras = 40 e tolerancia = 0.05.
func NovoAtaqueSAC(opcoes ...OpcoesSAC) *AtaqueSAC {
	o := OpcoesSAC{TamanhoBloco: 32, Amostras: 40, Tolerancia: 0.05}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueSAC{tamanhoBloco: o.TamanhoBloco, amostras: o.Amostras, tolerancia: o.Tolerancia}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueSAC) Nome() string {
	return "SAC (Strict Avalanche Criterion)"
}

// Executar roda o ataque.
func (a *AtaqueSAC) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	totalBits := a.tamanhoBloco * 8
	flips := make([]int, totalBits)
	tamanhoIv := alvo.TamanhoIv()
	total := 0

	for pos := 0; pos < tamanhoIv; pos++ {
		for bit := 0; bit < 8; bit++ {
			for s := 0; s < a.amostras; s++ {
				iv1 := seguranca.RandomBytes(tamanhoIv)
				iv2 := append([]byte(nil), iv1...)
				iv2[pos] ^= byte(1 << bit)

				ks1 := alvo.GerarKeystreamBruto(chave, iv1, "enc", a.tamanhoBloco)
				ks2 := alvo.GerarKeystreamBruto(chave, iv2, "enc", a.tamanhoBloco)

				for j := 0; j < totalBits; j++ {
					b1 := (ks1[j>>3] >> (7 - (j & 7))) & 1
					b2 := (ks2[j>>3] >> (7 - (j & 7))) & 1
					if b1 != b2 {
						flips[j]++
					}
				}
				total++
			}
		}
	}

	pior := -1
	piorDesvio := 0.0
	piorP := 0.5
	for j := 0; j < totalBits; j++ {
		p := float64(flips[j]) / float64(total)
		desvio := math.Abs(p - 0.5)
		if desvio > piorDesvio {
			piorDesvio = desvio
			pior = j
			piorP = p
		}
	}

	vulneravel := piorDesvio > a.tolerancia
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"pior bit de saída=%d: p=%.2f%% (esperado 50%%, tolerância ±%.1f%%); %d amostras por bit de entrada",
			pior, piorP*100, a.tolerancia*100, total,
		),
		Dados: map[string]any{"pior": pior, "pior_p": piorP, "desvio": piorDesvio},
	}, nil
}

package ataques

import (
	"fmt"
	"math"

	"criptografia/internal/seguranca"
)

// OpcoesCusum configura o AtaqueCusum.
type OpcoesCusum struct {
	Tamanho int
	LimiteZ float64
}

// AtaqueCusum aplica somas cumulativas (cusum, NIST SP800-22): converte os
// bits em passos +1/-1 e observa o maior desvio da caminhada aleatória.
type AtaqueCusum struct {
	tamanho int
	limiteZ float64
}

// NovoAtaqueCusum cria o ataque. Sem argumento, usa tamanho = 8192 e
// limiteZ = 4.0.
func NovoAtaqueCusum(opcoes ...OpcoesCusum) *AtaqueCusum {
	o := OpcoesCusum{Tamanho: 8192, LimiteZ: 4.0}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCusum{tamanho: o.Tamanho, limiteZ: o.LimiteZ}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCusum) Nome() string {
	return "Somas cumulativas (cusum)"
}

// Executar roda o ataque.
func (a *AtaqueCusum) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)

	soma := 0
	maxAbs := 0
	for i := 0; i < len(ks); i++ {
		by := ks[i]
		for b := 7; b >= 0; b-- {
			if ((by >> b) & 1) == 1 {
				soma++
			} else {
				soma--
			}
			if abs := int(math.Abs(float64(soma))); abs > maxAbs {
				maxAbs = abs
			}
		}
	}
	n := len(ks) * 8
	z := float64(maxAbs) / math.Sqrt(float64(n))
	vulneravel := z > a.limiteZ

	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevMedia
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"max|S|=%d sobre %d bits, max|S|/sqrt(n)=%.2f (limite=%.1f)",
			maxAbs, n, z, a.limiteZ,
		),
		Dados: map[string]any{"max_abs": maxAbs, "z": z},
	}, nil
}

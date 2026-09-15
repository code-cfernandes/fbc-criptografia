package ataques

import (
	"fmt"
	"math"

	"criptografia/internal/seguranca"
)

// OpcoesBIC configura o AtaqueBIC.
type OpcoesBIC struct {
	TamanhoBloco int
	Amostras     int
	Limite       float64
}

// AtaqueBIC (Bit Independence Criterion): pares de bits de saída não devem
// estar correlacionados quando a entrada muda. Mede o coeficiente phi entre
// cada par de bits de saída.
type AtaqueBIC struct {
	tamanhoBloco int
	amostras     int
	limite       float64
}

// NovoAtaqueBIC cria o ataque. Sem argumento, usa tamanhoBloco = 32,
// amostras = 300 e limite = 0.35.
func NovoAtaqueBIC(opcoes ...OpcoesBIC) *AtaqueBIC {
	o := OpcoesBIC{TamanhoBloco: 32, Amostras: 300, Limite: 0.35}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueBIC{tamanhoBloco: o.TamanhoBloco, amostras: o.Amostras, limite: o.Limite}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueBIC) Nome() string {
	return "BIC (Bit Independence Criterion)"
}

// Executar roda o ataque.
func (a *AtaqueBIC) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	totalBits := a.tamanhoBloco * 8
	tamanhoIv := alvo.TamanhoIv()

	amostrasFlips := make([][]byte, a.amostras)
	for s := 0; s < a.amostras; s++ {
		iv1 := seguranca.RandomBytes(tamanhoIv)
		iv2 := append([]byte(nil), iv1...)
		pos := seguranca.RandomInt(0, tamanhoIv-1)
		iv2[pos] ^= byte(1 << seguranca.RandomInt(0, 7))

		ks1 := alvo.GerarKeystreamBruto(chave, iv1, "enc", a.tamanhoBloco)
		ks2 := alvo.GerarKeystreamBruto(chave, iv2, "enc", a.tamanhoBloco)

		flips := make([]byte, totalBits)
		for j := 0; j < totalBits; j++ {
			b1 := (ks1[j>>3] >> (7 - (j & 7))) & 1
			b2 := (ks2[j>>3] >> (7 - (j & 7))) & 1
			if b1 != b2 {
				flips[j] = 1
			}
		}
		amostrasFlips[s] = flips
	}

	piorPhi := 0.0
	piorPar := [2]int{-1, -1}
	n := a.amostras

	for ai := 0; ai < totalBits; ai++ {
		for bi := ai + 1; bi < totalBits; bi++ {
			n11, n10, n01, n00 := 0, 0, 0, 0
			for s := 0; s < n; s++ {
				fa := amostrasFlips[s][ai]
				fb := amostrasFlips[s][bi]
				if fa == 1 && fb == 1 {
					n11++
				} else if fa == 1 && fb == 0 {
					n10++
				} else if fa == 0 && fb == 1 {
					n01++
				} else {
					n00++
				}
			}
			den := math.Sqrt(float64((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00)))
			phi := 0.0
			if den > 0 {
				phi = float64(n11*n00-n10*n01) / den
			}
			if math.Abs(phi) > math.Abs(piorPhi) {
				piorPhi = phi
				piorPar = [2]int{ai, bi}
			}
		}
	}

	vulneravel := math.Abs(piorPhi) > a.limite
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"maior |phi|=%.3f entre bits de saída [%d, %d] (limite %v); %d amostras",
			math.Abs(piorPhi), piorPar[0], piorPar[1], a.limite, n,
		),
		Dados: map[string]any{"pior_phi": piorPhi, "par": piorPar},
	}, nil
}

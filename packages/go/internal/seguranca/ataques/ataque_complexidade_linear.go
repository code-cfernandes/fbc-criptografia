package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesComplexidadeLinear configura o AtaqueComplexidadeLinear.
type OpcoesComplexidadeLinear struct {
	BitsPorAmostra int
	Amostras       int
	LimiteRelativo float64
}

// AtaqueComplexidadeLinear usa Berlekamp-Massey para calcular a complexidade
// linear (tamanho do menor LFSR que reproduz a sequência de bits).
type AtaqueComplexidadeLinear struct {
	bitsPorAmostra int
	amostras       int
	limiteRelativo float64
}

// NovoAtaqueComplexidadeLinear cria o ataque. Sem argumento, usa
// bitsPorAmostra = 1024, amostras = 5 e limiteRelativo = 0.4.
func NovoAtaqueComplexidadeLinear(opcoes ...OpcoesComplexidadeLinear) *AtaqueComplexidadeLinear {
	o := OpcoesComplexidadeLinear{BitsPorAmostra: 1024, Amostras: 5, LimiteRelativo: 0.4}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueComplexidadeLinear{
		bitsPorAmostra: o.BitsPorAmostra,
		amostras:       o.Amostras,
		limiteRelativo: o.LimiteRelativo,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueComplexidadeLinear) Nome() string {
	return "Complexidade linear (Berlekamp-Massey)"
}

// Executar roda o ataque.
func (a *AtaqueComplexidadeLinear) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())

	relativos := make([]float64, 0, a.amostras)
	pior := 1.0
	for i := 0; i < a.amostras; i++ {
		bytes := alvo.GerarKeystreamBruto(chave, seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.bitsPorAmostra/8)
		bits := a.paraBits(bytes, a.bitsPorAmostra)
		relativo := float64(a.berlekampMassey(bits)) / float64(a.bitsPorAmostra)
		relativos = append(relativos, relativo)
		if relativo < pior {
			pior = relativo
		}
	}

	media := 0.0
	for _, v := range relativos {
		media += v
	}
	media /= float64(len(relativos))

	vulneravel := pior < a.limiteRelativo
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevCritica
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"complexidade linear relativa: média=%.1f%%, pior=%.1f%% de %d bits (esperado ~50%%; limite>=%.0f%%)",
			media*100, pior*100, a.bitsPorAmostra, a.limiteRelativo*100,
		),
		Dados: map[string]any{"media": media, "pior": pior},
	}, nil
}

// paraBits converte bytes em bits, do mais significativo ao menos.
func (a *AtaqueComplexidadeLinear) paraBits(bytes []byte, limite int) []int {
	bits := make([]int, 0, limite)
	for i := 0; i < len(bytes) && len(bits) < limite; i++ {
		by := bytes[i]
		for b := 7; b >= 0; b-- {
			bits = append(bits, int((by>>b)&1))
		}
	}
	if len(bits) > limite {
		bits = bits[:limite]
	}
	return bits
}

// berlekampMassey calcula a complexidade linear sobre GF(2).
func (a *AtaqueComplexidadeLinear) berlekampMassey(s []int) int {
	n := len(s)
	c := make([]int, n)
	c[0] = 1
	b := make([]int, n)
	b[0] = 1
	l := 0
	m := -1

	for i := 0; i < n; i++ {
		d := s[i]
		for j := 1; j <= l; j++ {
			d ^= c[j] & s[i-j]
		}

		if d == 1 {
			t := make([]int, n)
			copy(t, c)
			shift := i - m
			for j := 0; j+shift < n; j++ {
				c[j+shift] ^= b[j]
			}
			if l <= i/2 {
				l = i + 1 - l
				m = i
				copy(b, t)
			}
		}
	}

	return l
}

package ataques

import (
	"fmt"
	"math"

	"criptografia/internal/seguranca"
)

// OpcoesEntropiaAproximada configura o AtaqueEntropiaAproximada.
type OpcoesEntropiaAproximada struct {
	Tamanho           int
	M                 int
	Controles         int
	AmostrasKeystream int
	LimiteZ           float64
}

// AtaqueEntropiaAproximada mede a entropia aproximada (ApEn) do keystream e a
// compara com um controle de bytes aleatórios nas mesmas condições.
type AtaqueEntropiaAproximada struct {
	tamanho           int
	m                 int
	controles         int
	amostrasKeystream int
	limiteZ           float64
}

// NovoAtaqueEntropiaAproximada cria o ataque. Sem argumento, usa tamanho = 4096,
// m = 8, controles = 12, amostrasKeystream = 3 e limiteZ = 5.0.
func NovoAtaqueEntropiaAproximada(opcoes ...OpcoesEntropiaAproximada) *AtaqueEntropiaAproximada {
	o := OpcoesEntropiaAproximada{Tamanho: 4096, M: 8, Controles: 12, AmostrasKeystream: 3, LimiteZ: 5.0}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueEntropiaAproximada{
		tamanho:           o.Tamanho,
		m:                 o.M,
		controles:         o.Controles,
		amostrasKeystream: o.AmostrasKeystream,
		limiteZ:           o.LimiteZ,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueEntropiaAproximada) Nome() string {
	return "Entropia aproximada (ApEn vs controle aleatório)"
}

// Executar roda o ataque.
func (a *AtaqueEntropiaAproximada) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chiControle := make([]float64, 0, a.controles)
	for c := 0; c < a.controles; c++ {
		chiControle = append(chiControle, a.estatistico(seguranca.RandomBytes(a.tamanho)))
	}
	mediaControle := 0.0
	for _, v := range chiControle {
		mediaControle += v
	}
	mediaControle /= float64(len(chiControle))
	variancia := 0.0
	for _, v := range chiControle {
		variancia += (v - mediaControle) * (v - mediaControle)
	}
	desvioControle := math.Sqrt(variancia / math.Max(1, float64(len(chiControle)-1)))

	chiKeystream := make([]float64, 0, a.amostrasKeystream)
	for k := 0; k < a.amostrasKeystream; k++ {
		ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)
		chiKeystream = append(chiKeystream, a.estatistico(ks))
	}
	mediaKeystream := 0.0
	for _, v := range chiKeystream {
		mediaKeystream += v
	}
	mediaKeystream /= float64(len(chiKeystream))

	z := 0.0
	if desvioControle > 0 {
		z = (mediaKeystream - mediaControle) / desvioControle
	}
	vulneravel := math.Abs(z) > a.limiteZ

	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevMedia
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"chi2 keystream=%.1f, controle=%.1f (sd=%.1f), z=%.2f (limite=%.1f)",
			mediaKeystream, mediaControle, desvioControle, z, a.limiteZ,
		),
		Dados: map[string]any{
			"chi_keystream": mediaKeystream,
			"chi_controle":  mediaControle,
			"z":             z,
		},
	}, nil
}

// estatistico calcula chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1).
func (a *AtaqueEntropiaAproximada) estatistico(bytes []byte) float64 {
	bits := a.paraBits(bytes)
	n := len(bits)
	apen := a.phi(bits, a.m, n) - a.phi(bits, a.m+1, n)
	return 2 * float64(n) * (math.Ln2 - apen)
}

// phi calcula a entropia aproximada para blocos de m bits.
func (a *AtaqueEntropiaAproximada) phi(bits []int, m, n int) float64 {
	total := 1 << m
	contagem := make([]int, total)
	janelas := n - m + 1

	for i := 0; i < janelas; i++ {
		v := 0
		for j := 0; j < m; j++ {
			v = (v << 1) | bits[i+j]
		}
		contagem[v]++
	}

	soma := 0.0
	for _, c := range contagem {
		if c > 0 {
			p := float64(c) / float64(janelas)
			soma += p * math.Log(p)
		}
	}

	return soma
}

// paraBits converte bytes em bits, do mais significativo ao menos.
func (a *AtaqueEntropiaAproximada) paraBits(bytes []byte) []int {
	bits := make([]int, 0, len(bytes)*8)
	for i := 0; i < len(bytes); i++ {
		by := bytes[i]
		for b := 7; b >= 0; b-- {
			bits = append(bits, int((by>>b)&1))
		}
	}
	return bits
}

package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesSerialBits configura o AtaqueSerialBits.
type OpcoesSerialBits struct {
	Tamanho int
	Ordens  []int
}

// AtaqueSerialBits testa a frequência de padrões sobrepostos de m bits (m=2,3,4).
// Um gerador bom distribui todos os 2^m padrões de forma uniforme; estruturas
// locais aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
type AtaqueSerialBits struct {
	tamanho int
	ordens  []int
}

// NovoAtaqueSerialBits cria o ataque. Sem argumento, usa tamanho = 4096 e
// ordens = [2, 3, 4].
func NovoAtaqueSerialBits(opcoes ...OpcoesSerialBits) *AtaqueSerialBits {
	o := OpcoesSerialBits{Tamanho: 4096, Ordens: []int{2, 3, 4}}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueSerialBits{tamanho: o.Tamanho, ordens: o.Ordens}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueSerialBits) Nome() string {
	return "Teste serial (padrões de bits sobrepostos)"
}

// Executar roda o ataque.
func (a *AtaqueSerialBits) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)
	bits := a.paraBits(ks)
	n := len(bits)

	problemas := []string{}
	dados := map[string]any{}

	for _, m := range a.ordens {
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

		esperado := float64(janelas) / float64(total)
		chi2 := 0.0
		for _, c := range contagem {
			diff := float64(c) - esperado
			chi2 += (diff * diff) / esperado
		}
		dof := float64(total - 1)
		z := (math.Cbrt(chi2/dof) - (1 - 2/(9*dof))) / math.Sqrt(2/(9*dof))
		dados[fmt.Sprintf("m%d", m)] = map[string]any{"chi2": chi2, "z": z}

		if z > 6.0 {
			problemas = append(problemas, fmt.Sprintf("m=%d chi2=%.1f (z=%.1f)", m, chi2, z))
		}
	}

	if len(problemas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevMedia,
			Detalhes:   strings.Join(problemas, "; "),
			Dados:      dados,
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   "Padrões sobrepostos de 2/3/4 bits com frequência uniforme",
		Dados:      dados,
	}, nil
}

// paraBits converte bytes em bits, do mais significativo ao menos.
func (a *AtaqueSerialBits) paraBits(bytes []byte) []int {
	bits := make([]int, 0, len(bytes)*8)
	for i := 0; i < len(bytes); i++ {
		by := bytes[i]
		for b := 7; b >= 0; b-- {
			bits = append(bits, int((by>>b)&1))
		}
	}
	return bits
}

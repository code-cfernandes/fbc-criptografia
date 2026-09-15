package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesDistribuicaoPorPosicao configura o AtaqueDistribuicaoPorPosicao.
type OpcoesDistribuicaoPorPosicao struct {
	AmostrasDeBlocos int
	TamanhoBloco     int
}

// AtaqueDistribuicaoPorPosicao faz qui-quadrado POR POSIÇÃO do bloco, onde
// uma posição específica pode ter viés forte mesmo que a soma global pareça
// uniforme.
type AtaqueDistribuicaoPorPosicao struct {
	amostrasDeBlocos int
	tamanhoBloco     int
}

// NovoAtaqueDistribuicaoPorPosicao cria o ataque. Sem argumento, usa
// amostrasDeBlocos = 2000 e tamanhoBloco = 32.
func NovoAtaqueDistribuicaoPorPosicao(opcoes ...OpcoesDistribuicaoPorPosicao) *AtaqueDistribuicaoPorPosicao {
	o := OpcoesDistribuicaoPorPosicao{AmostrasDeBlocos: 2000, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueDistribuicaoPorPosicao{amostrasDeBlocos: o.AmostrasDeBlocos, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueDistribuicaoPorPosicao) Nome() string {
	return "Distribuição de bytes por posição do bloco"
}

// Executar roda o ataque.
func (a *AtaqueDistribuicaoPorPosicao) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())

	contagens := make([][]int, a.tamanhoBloco)
	for p := 0; p < a.tamanhoBloco; p++ {
		contagens[p] = make([]int, 256)
	}

	for i := 0; i < a.amostrasDeBlocos; i++ {
		ks := alvo.GerarKeystreamBruto(chave, seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanhoBloco)
		for p := 0; p < a.tamanhoBloco; p++ {
			contagens[p][ks[p]]++
		}
	}

	esperado := float64(a.amostrasDeBlocos) / 256
	problemas := []string{}
	pior := 0.0

	for p := 0; p < len(contagens); p++ {
		chi2 := 0.0
		for _, v := range contagens[p] {
			diff := float64(v) - esperado
			chi2 += (diff * diff) / esperado
		}
		if chi2 > pior {
			pior = chi2
		}
		z := (chi2 - 255) / math.Sqrt(510)
		if z > 4.0 {
			problemas = append(problemas, fmt.Sprintf("posição %d chi2=%.1f", p, chi2))
		}
	}

	if len(problemas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevMedia,
			Detalhes:   strings.Join(problemas, "; "),
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes: fmt.Sprintf(
			"Todas as %d posições uniformes (pior chi2=%.1f, esperado ~255)",
			a.tamanhoBloco, pior,
		),
	}, nil
}

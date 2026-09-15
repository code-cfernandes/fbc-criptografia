package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesCorrelacaoPosicoes configura o AtaqueCorrelacaoPosicoes.
type OpcoesCorrelacaoPosicoes struct {
	Amostras         int
	TamanhoBloco     int
	LimiteCorrelacao float64
}

// AtaqueCorrelacaoPosicoes verifica se posições diferentes dentro do mesmo
// bloco de 32 bytes saem correlacionadas.
type AtaqueCorrelacaoPosicoes struct {
	amostras         int
	tamanhoBloco     int
	limiteCorrelacao float64
}

// NovoAtaqueCorrelacaoPosicoes cria o ataque. Sem argumento, usa
// amostras = 3000, tamanhoBloco = 32 e limiteCorrelacao = 0.15.
func NovoAtaqueCorrelacaoPosicoes(opcoes ...OpcoesCorrelacaoPosicoes) *AtaqueCorrelacaoPosicoes {
	o := OpcoesCorrelacaoPosicoes{Amostras: 3000, TamanhoBloco: 32, LimiteCorrelacao: 0.15}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCorrelacaoPosicoes{
		amostras:         o.Amostras,
		tamanhoBloco:     o.TamanhoBloco,
		limiteCorrelacao: o.LimiteCorrelacao,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCorrelacaoPosicoes) Nome() string {
	return "Correlação entre posições do bloco"
}

// Executar roda o ataque.
func (a *AtaqueCorrelacaoPosicoes) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())

	blocos := make([][]byte, 0, a.amostras)
	for i := 0; i < a.amostras; i++ {
		blocos = append(blocos, alvo.GerarKeystreamBruto(chave, seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanhoBloco))
	}

	suspeitos := []string{}
	pior := 0.0

	for x := 0; x < a.tamanhoBloco; x++ {
		for y := x + 1; y < a.tamanhoBloco; y++ {
			corr := a.pearson(blocos, x, y)
			if math.Abs(corr) > math.Abs(pior) {
				pior = corr
			}
			if math.Abs(corr) > a.limiteCorrelacao {
				suspeitos = append(suspeitos, fmt.Sprintf("posições %d-%d (r=%.3f)", x, y, corr))
			}
		}
	}

	if len(suspeitos) > 0 {
		limite := min(10, len(suspeitos))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes:   fmt.Sprintf("%d par(es) correlacionado(s): %s", len(suspeitos), strings.Join(suspeitos[:limite], "; ")),
			Dados:      map[string]any{"suspeitos": suspeitos},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes: fmt.Sprintf(
			"Nenhum par de posições correlacionado acima de %.2f (pior |r|=%.3f)",
			a.limiteCorrelacao, math.Abs(pior),
		),
	}, nil
}

// pearson calcula o coeficiente de correlação de Pearson entre duas posições.
func (a *AtaqueCorrelacaoPosicoes) pearson(blocos [][]byte, x, y int) float64 {
	n := len(blocos)
	ma := 0.0
	mb := 0.0
	for _, d := range blocos {
		ma += float64(d[x])
		mb += float64(d[y])
	}
	ma /= float64(n)
	mb /= float64(n)

	num := 0.0
	da := 0.0
	db := 0.0
	for _, d := range blocos {
		xa := float64(d[x]) - ma
		xb := float64(d[y]) - mb
		num += xa * xb
		da += xa * xa
		db += xb * xb
	}

	if da > 0 && db > 0 {
		return num / math.Sqrt(da*db)
	}
	return 0.0
}

package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesEntropiaIV configura o AtaqueEntropiaIV.
type OpcoesEntropiaIV struct {
	Amostras int
}

// AtaqueEntropiaIV detecta previsibilidade no IV com três sinais: distribuição
// de bytes, monotonicidade do primeiro byte e repetição interna.
type AtaqueEntropiaIV struct {
	amostras int
}

// NovoAtaqueEntropiaIV cria o ataque. Sem argumento, usa amostras = 2000.
func NovoAtaqueEntropiaIV(opcoes ...OpcoesEntropiaIV) *AtaqueEntropiaIV {
	o := OpcoesEntropiaIV{Amostras: 2000}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueEntropiaIV{amostras: o.Amostras}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueEntropiaIV) Nome() string {
	return "Entropia e previsibilidade do IV"
}

// Executar roda o ataque.
func (a *AtaqueEntropiaIV) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ivs := make([][]byte, 0, a.amostras)
	for i := 0; i < a.amostras; i++ {
		token, err := alvo.Encrypt([]byte("X"))
		if err != nil {
			continue
		}
		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		ivs = append(ivs, alvo.Decompor(decodificado).IV)
	}

	problemas := []string{}

	// Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
	contagem := make([]int, 256)
	total := 0
	for _, iv := range ivs {
		for i := 0; i < len(iv); i++ {
			contagem[iv[i]]++
			total++
		}
	}
	esperado := float64(total) / 256
	qui2 := 0.0
	for _, c := range contagem {
		diff := float64(c) - esperado
		qui2 += (diff * diff) / esperado
	}
	if qui2 > 330 {
		problemas = append(problemas, fmt.Sprintf("distribuição de bytes suspeita (qui-quadrado=%.1f, >330 é suspeito)", qui2))
	}

	// Sinal 2: monotonicidade do primeiro byte
	crescentes := 0
	for i := 1; i < len(ivs); i++ {
		if ivs[i][0] > ivs[i-1][0] {
			crescentes++
		}
	}
	proporcaoCrescente := float64(crescentes) / float64(len(ivs)-1)
	if proporcaoCrescente > 0.65 || proporcaoCrescente < 0.35 {
		problemas = append(problemas, fmt.Sprintf(
			"primeiro byte do IV parece monotônico (%.0f%% das vezes crescente; aleatório ficaria perto de 50%%)",
			proporcaoCrescente*100,
		))
	}

	// Sinal 3: bytes duplicados dentro do MESMO IV
	semRepeticaoInterna := 0
	for _, iv := range ivs {
		unicos := map[byte]bool{}
		for _, b := range iv {
			unicos[b] = true
		}
		if len(unicos) == len(iv) {
			semRepeticaoInterna++
		}
	}
	proporcaoSemRepeticao := float64(semRepeticaoInterna) / float64(len(ivs))
	if proporcaoSemRepeticao > 0.9 || proporcaoSemRepeticao < 0.5 {
		problemas = append(problemas, fmt.Sprintf(
			"%.0f%% dos IVs não têm nenhum byte repetido internamente (esperado ~72%% para 16 bytes aleatórios)",
			proporcaoSemRepeticao*100,
		))
	}

	if len(problemas) > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes:   strings.Join(problemas, "; "),
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes: fmt.Sprintf(
			"qui-quadrado=%.1f, %.0f%% primeiro-byte-crescente (~50%% esperado), %.0f%% sem repetição interna (~72%% esperado) - tudo consistente com IV aleatório",
			qui2, proporcaoCrescente*100, proporcaoSemRepeticao*100,
		),
	}, nil
}

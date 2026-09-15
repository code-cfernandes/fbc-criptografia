package ataques

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesChavesFracas configura o AtaqueChavesFracas.
type OpcoesChavesFracas struct {
	Tamanho        int
	ToleranciaBits float64
}

// AtaqueChavesFracas busca chaves degeneradas/estruturadas que não devem
// produzir keystream anômalo (repetição, viés de bits ou distribuição
// distorcida).
type AtaqueChavesFracas struct {
	tamanho        int
	toleranciaBits float64
}

// NovoAtaqueChavesFracas cria o ataque. Sem argumento, usa tamanho = 2048 e
// toleranciaBits = 0.05.
func NovoAtaqueChavesFracas(opcoes ...OpcoesChavesFracas) *AtaqueChavesFracas {
	o := OpcoesChavesFracas{Tamanho: 2048, ToleranciaBits: 0.05}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueChavesFracas{tamanho: o.Tamanho, toleranciaBits: o.ToleranciaBits}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueChavesFracas) Nome() string {
	return "Chaves fracas (busca dirigida)"
}

type casoChaveFraca struct {
	nome  string
	chave []byte
}

// Executar roda o ataque.
func (a *AtaqueChavesFracas) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	length := len(alvo.ChaveDeTeste())

	alternada := func(x, y byte) []byte {
		out := make([]byte, length)
		for i := 0; i < length; i++ {
			if i%2 == 0 {
				out[i] = x
			} else {
				out[i] = y
			}
		}
		return out
	}
	incremental := make([]byte, length)
	for i := 0; i < length; i++ {
		incremental[i] = byte(i & 0xff)
	}
	umBit := make([]byte, length)
	umBit[0] = 1

	casos := []casoChaveFraca{
		{nome: "zeros", chave: make([]byte, length)},
		{nome: "0xFF", chave: bytes.Repeat([]byte{0xff}, length)},
		{nome: "alternada AA/55", chave: alternada(0xaa, 0x55)},
		{nome: "incremental", chave: incremental},
		{nome: "um bit", chave: umBit},
		{nome: "byte repetido 0x01", chave: bytes.Repeat([]byte{0x01}, length)},
		{nome: "padrão AB", chave: alternada(0x41, 0x42)},
	}

	ivFixo := make([]byte, alvo.TamanhoIv())
	anomalias := []string{}

	for _, c := range casos {
		ks := alvo.GerarKeystreamBruto(c.chave, ivFixo, "enc", a.tamanho)

		blocos := map[string]bool{}
		repetidos := 0
		for i := 0; i+32 <= len(ks); i += 32 {
			hexStr := hex.EncodeToString(ks[i : i+32])
			if blocos[hexStr] {
				repetidos++
			} else {
				blocos[hexStr] = true
			}
		}

		fracaoUns := float64(seguranca.ContarBitsBuffer(ks)) / float64(len(ks)*8)
		desvioBits := math.Abs(fracaoUns - 0.5)

		if repetidos > 0 {
			anomalias = append(anomalias, fmt.Sprintf("%s: %d bloco(s) repetido(s)", c.nome, repetidos))
		}
		if desvioBits > a.toleranciaBits {
			anomalias = append(anomalias, fmt.Sprintf("%s: viés de bits %.1f%%", c.nome, fracaoUns*100))
		}
	}

	vulneravel := len(anomalias) > 0
	severidade := seguranca.SevInfo
	detalhes := fmt.Sprintf("Nenhuma das %d chaves fracas produziu keystream anômalo (%d bytes cada)", len(casos), a.tamanho)
	if vulneravel {
		severidade = seguranca.SevAlta
		detalhes = "Anomalias: " + strings.Join(anomalias[:min(5, len(anomalias))], "; ")
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"anomalias": anomalias},
	}, nil
}

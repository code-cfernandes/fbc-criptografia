package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesPreditorDeBits configura o AtaquePreditorDeBits.
type OpcoesPreditorDeBits struct {
	Tamanho    int
	Contexto   int
	LimiteTaxa float64
}

// AtaquePreditorDeBits treina um preditor por contexto (os k bits anteriores)
// na primeira metade do keystream e mede a taxa de acerto na segunda metade.
// Para um gerador sem memória/correlação local a taxa fica em ~50%.
type AtaquePreditorDeBits struct {
	tamanho    int
	contexto   int
	limiteTaxa float64
}

// NovoAtaquePreditorDeBits cria o ataque. Sem argumento, usa tamanho = 16384,
// contexto = 8 e limiteTaxa = 0.55.
func NovoAtaquePreditorDeBits(opcoes ...OpcoesPreditorDeBits) *AtaquePreditorDeBits {
	o := OpcoesPreditorDeBits{Tamanho: 16384, Contexto: 8, LimiteTaxa: 0.55}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaquePreditorDeBits{tamanho: o.Tamanho, contexto: o.Contexto, limiteTaxa: o.LimiteTaxa}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaquePreditorDeBits) Nome() string {
	return "Previsibilidade de bits (preditor por contexto)"
}

// Executar roda o ataque.
func (a *AtaquePreditorDeBits) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)
	bits := a.paraBits(ks)
	n := len(bits)
	k := a.contexto
	total := 1 << k
	metade := n / 2

	uns := make([]int, total)
	cont := make([]int, total)
	for i := k; i < metade; i++ {
		ctx := a.contextoDe(bits, i, k)
		uns[ctx] += bits[i]
		cont[ctx]++
	}

	acertos := 0
	testes := 0
	for i := metade; i < n; i++ {
		ctx := a.contextoDe(bits, i, k)
		if cont[ctx] == 0 {
			continue
		}
		predicao := 0
		if uns[ctx]*2 > cont[ctx] {
			predicao = 1
		}
		if predicao == bits[i] {
			acertos++
		}
		testes++
	}

	taxa := 0.5
	if testes > 0 {
		taxa = float64(acertos) / float64(testes)
	}
	vulneravel := taxa > a.limiteTaxa

	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"taxa de acerto=%.2f%% com contexto de %d bits (esperado ~50%%, limite=%.0f%%) sobre %d testes",
			taxa*100, k, a.limiteTaxa*100, testes,
		),
		Dados: map[string]any{"taxa": taxa, "testes": testes},
	}, nil
}

// contextoDe monta o contexto de k bits anteriores à posição i.
func (a *AtaquePreditorDeBits) contextoDe(bits []int, i, k int) int {
	ctx := 0
	for j := i - k; j < i; j++ {
		ctx = (ctx << 1) | bits[j]
	}
	return ctx
}

// paraBits converte bytes em bits, do mais significativo ao menos.
func (a *AtaquePreditorDeBits) paraBits(bytes []byte) []int {
	bits := make([]int, 0, len(bytes)*8)
	for i := 0; i < len(bytes); i++ {
		by := bytes[i]
		for b := 7; b >= 0; b-- {
			bits = append(bits, int((by>>b)&1))
		}
	}
	return bits
}

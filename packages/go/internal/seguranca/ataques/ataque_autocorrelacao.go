package ataques

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesAutocorrelacao configura o AtaqueAutocorrelacao.
type OpcoesAutocorrelacao struct {
	Tamanho      int
	TamanhoBloco int
}

// AtaqueAutocorrelacao olha o keystream LONGO: correlação serial entre bytes
// vizinhos, autocorrelação em lags (inclusive múltiplos do bloco), blocos de
// 32 bytes repetidos e o balanço global de bits.
type AtaqueAutocorrelacao struct {
	tamanho      int
	tamanhoBloco int
}

// NovoAtaqueAutocorrelacao cria o ataque. Sem argumento, usa tamanho = 8192 e
// tamanhoBloco = 32.
func NovoAtaqueAutocorrelacao(opcoes ...OpcoesAutocorrelacao) *AtaqueAutocorrelacao {
	o := OpcoesAutocorrelacao{Tamanho: 8192, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueAutocorrelacao{tamanho: o.Tamanho, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAutocorrelacao) Nome() string {
	return "Autocorrelação e periodicidade do keystream"
}

// Executar roda o ataque.
func (a *AtaqueAutocorrelacao) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)

	serial := a.correlacao(ks, 1)

	type lagSuspeito struct {
		lag int
		c   float64
	}
	suspeitos := []lagSuspeito{}
	for _, lag := range []int{2, 4, 8, 16, 32, 64, 128, 256} {
		c := a.correlacao(ks, lag)
		if math.Abs(c) > 0.1 {
			suspeitos = append(suspeitos, lagSuspeito{lag: lag, c: c})
		}
	}

	blocos := make([][]byte, 0)
	for i := 0; i < len(ks); i += a.tamanhoBloco {
		fim := i + a.tamanhoBloco
		if fim > len(ks) {
			fim = len(ks)
		}
		blocos = append(blocos, ks[i:fim])
	}
	unicos := map[string]bool{}
	for _, b := range blocos {
		unicos[hex.EncodeToString(b)] = true
	}
	blocosRepetidos := len(blocos) - len(unicos)

	uns := seguranca.ContarBitsBuffer(ks)
	fracaoUns := float64(uns) / float64(len(ks)*8)

	problemas := []string{}
	if math.Abs(serial) > 0.1 {
		problemas = append(problemas, fmt.Sprintf("correlação serial=%.3f", serial))
	}
	if len(suspeitos) > 0 {
		lags := make([]string, len(suspeitos))
		for i, s := range suspeitos {
			lags[i] = fmt.Sprint(s.lag)
		}
		problemas = append(problemas, "autocorrelação em lag(s) "+strings.Join(lags, ", "))
	}
	if blocosRepetidos > 0 {
		problemas = append(problemas, fmt.Sprintf("%d bloco(s) de %d bytes repetido(s)", blocosRepetidos, a.tamanhoBloco))
	}
	if fracaoUns < 0.45 || fracaoUns > 0.55 {
		problemas = append(problemas, fmt.Sprintf("balanço de bits=%.1f%% de 1s", fracaoUns*100))
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
			"serial=%.3f, nenhum lag com correlação >10%%, 0 blocos repetidos em %d, %.1f%% de bits 1",
			serial, len(blocos), fracaoUns*100,
		),
	}, nil
}

// correlacao calcula a autocorrelação normalizada no lag indicado.
func (a *AtaqueAutocorrelacao) correlacao(s []byte, lag int) float64 {
	n := len(s)
	if n <= lag {
		return 0.0
	}

	soma := 0.0
	for i := 0; i < n; i++ {
		soma += float64(s[i])
	}
	media := soma / float64(n)

	num := 0.0
	den := 0.0
	for i := 0; i < n; i++ {
		den += (float64(s[i]) - media) * (float64(s[i]) - media)
	}
	for i := 0; i < n-lag; i++ {
		num += (float64(s[i]) - media) * (float64(s[i+lag]) - media)
	}

	if den > 0 {
		return num / den
	}
	return 0.0
}

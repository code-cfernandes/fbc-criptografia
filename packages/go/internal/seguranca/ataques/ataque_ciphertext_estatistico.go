package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesCiphertextEstatistico configura o AtaqueCiphertextEstatistico.
type OpcoesCiphertextEstatistico struct {
	Amostras     int
	TamanhoTexto int
	ZLimite      float64
}

// AtaqueCiphertextEstatistico analisa só o ciphertext (não o keystream):
// distribuição de bytes (qui-quadrado), teste de runs nos bits e
// autocorrelação lag-1.
type AtaqueCiphertextEstatistico struct {
	amostras     int
	tamanhoTexto int
	zLimite      float64
}

// NovoAtaqueCiphertextEstatistico cria o ataque. Sem argumento, usa
// amostras = 200, tamanhoTexto = 64 e zLimite = 4.
func NovoAtaqueCiphertextEstatistico(opcoes ...OpcoesCiphertextEstatistico) *AtaqueCiphertextEstatistico {
	o := OpcoesCiphertextEstatistico{Amostras: 200, TamanhoTexto: 64, ZLimite: 4}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCiphertextEstatistico{amostras: o.Amostras, tamanhoTexto: o.TamanhoTexto, zLimite: o.ZLimite}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCiphertextEstatistico) Nome() string {
	return "Estatística do ciphertext (chi²/runs/autocorrelação)"
}

// Executar roda o ataque.
func (a *AtaqueCiphertextEstatistico) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	contagem := make([]int, 256)
	bytesAcum := []byte{}

	for s := 0; s < a.amostras; s++ {
		texto := seguranca.RandomBytes(a.tamanhoTexto)
		token, err := alvo.Encrypt(texto)
		if err != nil {
			continue
		}
		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		campos := alvo.Decompor(decodificado)
		for _, b := range campos.Ciphertext {
			contagem[b]++
			bytesAcum = append(bytesAcum, b)
		}
	}

	total := len(bytesAcum)
	esperado := float64(total) / 256
	chi2 := 0.0
	for _, c := range contagem {
		d := float64(c) - esperado
		chi2 += (d * d) / esperado
	}

	uns := 0
	bits := make([]int, 0, total*8)
	for _, b := range bytesAcum {
		for k := 7; k >= 0; k-- {
			bit := int((b >> k) & 1)
			bits = append(bits, bit)
			uns += bit
		}
	}
	n := len(bits)
	pi := float64(uns) / float64(n)
	runs := 1
	for i := 1; i < n; i++ {
		if bits[i] != bits[i-1] {
			runs++
		}
	}
	esperadoRuns := 2 * float64(n) * pi * (1 - pi)
	desvioRuns := 2 * math.Sqrt(2*float64(n)) * pi * (1 - pi)
	zRuns := 0.0
	if desvioRuns > 0 {
		zRuns = math.Abs(float64(runs)-esperadoRuns) / desvioRuns
	}

	media := 0.0
	for _, b := range bytesAcum {
		media += float64(b)
	}
	media /= float64(total)
	num := 0.0
	den := 0.0
	for i := 0; i < total; i++ {
		den += (float64(bytesAcum[i]) - media) * (float64(bytesAcum[i]) - media)
	}
	for i := 0; i < total-1; i++ {
		num += (float64(bytesAcum[i]) - media) * (float64(bytesAcum[i+1]) - media)
	}
	autocorr := 0.0
	if den > 0 {
		autocorr = num / den
	}

	problemas := []string{}
	if chi2 > 330 {
		problemas = append(problemas, fmt.Sprintf("qui-quadrado=%.1f (>330 suspeito)", chi2))
	}
	if zRuns > a.zLimite {
		problemas = append(problemas, fmt.Sprintf("runs z=%.2f", zRuns))
	}
	if math.Abs(autocorr) > 0.1 {
		problemas = append(problemas, fmt.Sprintf("autocorrelação=%.3f", autocorr))
	}

	vulneravel := len(problemas) > 0
	severidade := seguranca.SevInfo
	detalhes := fmt.Sprintf(
		"qui-quadrado=%.1f sobre %d bytes, runs z=%.2f, autocorrelação=%.3f - todos dentro do esperado",
		chi2, total, zRuns, autocorr,
	)
	if vulneravel {
		severidade = seguranca.SevMedia
		detalhes = strings.Join(problemas, "; ")
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"chi2": chi2, "runs_z": zRuns, "autocorrelacao": autocorr},
	}, nil
}

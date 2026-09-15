package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesBateriaEstatistica configura o AtaqueBateriaEstatistica.
type OpcoesBateriaEstatistica struct {
	Tamanho int
	ZLimite float64
}

// AtaqueBateriaEstatistica aplica uma bateria estatística no keystream
// (inspirada em NIST SP800-22): monobit, frequência por posição de bit, runs e
// frequência por bloco.
type AtaqueBateriaEstatistica struct {
	tamanho int
	zLimite float64
}

// NovoAtaqueBateriaEstatistica cria o ataque. Sem argumento, usa
// tamanho = 16384 e zLimite = 4.0.
func NovoAtaqueBateriaEstatistica(opcoes ...OpcoesBateriaEstatistica) *AtaqueBateriaEstatistica {
	o := OpcoesBateriaEstatistica{Tamanho: 16384, ZLimite: 4.0}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueBateriaEstatistica{tamanho: o.Tamanho, zLimite: o.ZLimite}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueBateriaEstatistica) Nome() string {
	return "Bateria estatística de bits (monobit/runs/blocos)"
}

// Executar roda o ataque.
func (a *AtaqueBateriaEstatistica) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ks := alvo.GerarKeystreamBruto([]byte(alvo.ChaveDeTeste()), seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanho)

	bits := a.paraBits(ks)
	n := len(bits)
	problemas := []string{}
	dados := map[string]any{}

	// 1) Monobit: soma +1/-1
	soma := 0
	for _, b := range bits {
		if b == 1 {
			soma++
		} else {
			soma--
		}
	}
	zMonobit := math.Abs(float64(soma)) / math.Sqrt(float64(n))
	dados["monobit_z"] = zMonobit
	if zMonobit > a.zLimite {
		problemas = append(problemas, fmt.Sprintf("monobit z=%.2f", zMonobit))
	}

	// 2) Frequência por posição de bit
	unsPorPos := make([]int, 8)
	contaPorPos := make([]int, 8)
	for i := 0; i < len(ks); i++ {
		by := ks[i]
		for b := 0; b < 8; b++ {
			if ((by >> b) & 1) == 1 {
				unsPorPos[b]++
			}
			contaPorPos[b]++
		}
	}
	posViesadas := map[int]float64{}
	for b := 0; b < 8; b++ {
		frac := float64(unsPorPos[b]) / float64(contaPorPos[b])
		z := math.Abs(frac-0.5) / (0.5 / math.Sqrt(float64(contaPorPos[b])))
		if z > a.zLimite {
			posViesadas[b] = frac
		}
	}
	dados["bit_posicao_viesadas"] = posViesadas
	if len(posViesadas) > 0 {
		posicoes := make([]string, 0, len(posViesadas))
		for b := 0; b < 8; b++ {
			if _, ok := posViesadas[b]; ok {
				posicoes = append(posicoes, fmt.Sprint(b))
			}
		}
		problemas = append(problemas, "viés por posição de bit: "+strings.Join(posicoes, ", "))
	}

	// 3) Runs test
	runsZ := 0.0
	pi := 0.0
	for _, b := range bits {
		pi += float64(b)
	}
	pi /= float64(n)
	if math.Abs(pi-0.5) < 2/math.Sqrt(float64(n)) {
		runs := 1
		for i := 1; i < n; i++ {
			if bits[i] != bits[i-1] {
				runs++
			}
		}
		esperado := 2 * float64(n) * pi * (1 - pi)
		desvio := 2 * math.Sqrt(2*float64(n)) * pi * (1 - pi)
		runsZ = math.Abs(float64(runs)-esperado) / desvio
		dados["runs_z"] = runsZ
		if runsZ > a.zLimite {
			problemas = append(problemas, fmt.Sprintf("runs z=%.2f", runsZ))
		}
	}

	// 4) Frequência por bloco (M = 128 bits)
	blocosChi2 := 0.0
	m := 128
	numBlocos := n / m
	if numBlocos > 0 {
		chi := 0.0
		for i := 0; i < numBlocos; i++ {
			uns := 0
			for j := 0; j < m; j++ {
				uns += bits[i*m+j]
			}
			chi += (float64(uns)/float64(m) - 0.5) * (float64(uns)/float64(m) - 0.5)
		}
		chi *= 4 * float64(m)
		zBlocos := (chi - float64(numBlocos)) / math.Sqrt(2*float64(numBlocos))
		blocosChi2 = chi
		dados["blocos_chi2"] = chi
		dados["blocos_z"] = zBlocos
		if zBlocos > a.zLimite {
			problemas = append(problemas, fmt.Sprintf("frequência por bloco chi2=%.1f", chi))
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
		Detalhes: fmt.Sprintf(
			"monobit z=%.2f, runs z=%.2f, blocos chi2=%.1f - todos abaixo do limite z=%.0f",
			zMonobit, runsZ, blocosChi2, a.zLimite,
		),
		Dados: dados,
	}, nil
}

// paraBits converte bytes em bits, do mais significativo ao menos.
func (a *AtaqueBateriaEstatistica) paraBits(bytes []byte) []int {
	bits := make([]int, 0, len(bytes)*8)
	for i := 0; i < len(bytes); i++ {
		by := bytes[i]
		for b := 7; b >= 0; b-- {
			bits = append(bits, int((by>>b)&1))
		}
	}
	return bits
}

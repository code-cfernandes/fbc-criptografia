package ataques

import (
	"fmt"
	"math"
	"sort"
	"time"

	"criptografia/internal/seguranca"
)

// OpcoesTiming configura o AtaqueTiming.
type OpcoesTiming struct {
	RepeticoesPorGrupo int
}

// AtaqueTiming compara o tempo médio de decrypt() quando o campo de integridade
// erra no início versus no fim. Uma diferença estatisticamente clara indica
// comparação vulnerável a timing.
type AtaqueTiming struct {
	repeticoesPorGrupo int
}

// NovoAtaqueTiming cria o ataque. Sem argumento, usa repeticoesPorGrupo = 400.
func NovoAtaqueTiming(opcoes ...OpcoesTiming) *AtaqueTiming {
	o := OpcoesTiming{RepeticoesPorGrupo: 400}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueTiming{repeticoesPorGrupo: o.RepeticoesPorGrupo}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueTiming) Nome() string {
	return "Timing da verificação de integridade"
}

// Executar roda o ataque.
func (a *AtaqueTiming) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	token, err := alvo.Encrypt([]byte("MENSAGEM_PARA_TESTE_DE_TIMING"))
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
	if err != nil {
		return seguranca.ResultadoAtaque{}, err
	}
	campos := alvo.Decompor(decodificado)
	tamanhoIntegridade := len(campos.Integridade)

	medirGrupo := func(posicaoErro int) int64 {
		tempos := make([]int64, 0, a.repeticoesPorGrupo)
		for r := 0; r < a.repeticoesPorGrupo; r++ {
			integridade := append([]byte(nil), campos.Integridade...)
			integridade[posicaoErro] ^= 0x01
			camposAdulterados := seguranca.CamposToken{
				Integridade: integridade,
				Ciphertext:  campos.Ciphertext,
				IV:          campos.IV,
			}
			tokenAdulterado := alvo.Prefixo() + alvo.Base64urlEncode(alvo.Recompor(camposAdulterados))

			inicio := time.Now()
			_, _ = alvo.Decrypt(tokenAdulterado)
			tempos = append(tempos, time.Since(inicio).Nanoseconds())
		}
		sort.Slice(tempos, func(i, j int) bool { return tempos[i] < tempos[j] })
		return tempos[len(tempos)/2]
	}

	medianasA := make([]int64, 0, 8)
	medianasB := make([]int64, 0, 8)
	for rodada := 0; rodada < 8; rodada++ {
		medianasA = append(medianasA, medirGrupo(0))
		medianasB = append(medianasB, medirGrupo(tamanhoIntegridade-1))
	}

	somaA := int64(0)
	for _, v := range medianasA {
		somaA += v
	}
	somaB := int64(0)
	for _, v := range medianasB {
		somaB += v
	}
	medianaA := float64(somaA) / float64(len(medianasA))
	medianaB := float64(somaB) / float64(len(medianasB))
	diferencaRelativa := math.Abs(medianaA-medianaB) / math.Max(medianaA, medianaB)

	vulneravel := diferencaRelativa > 0.15

	severidade := seguranca.SevInfo
	sufixo := "Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal)."
	if vulneravel {
		severidade = seguranca.SevMedia
		sufixo = "Diferença suspeita - investigar se a comparação usa hash_equals()."
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"mediana erro-no-início=%.0fns, mediana erro-no-fim=%.0fns, diferença relativa=%.1f%% (limite=15%%). %s",
			medianaA, medianaB, diferencaRelativa*100, sufixo,
		),
		Dados: map[string]any{"mediana_inicio_ns": medianaA, "mediana_fim_ns": medianaB},
	}, nil
}

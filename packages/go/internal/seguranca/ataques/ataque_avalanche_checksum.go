package ataques

import (
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesAvalancheChecksum configura o AtaqueAvalancheChecksum.
type OpcoesAvalancheChecksum struct {
	MensagensPorCombinacao int
	TamanhoEntrada         int
	LimiteMedia            float64
	LimitePiorCaso         float64
}

// AtaqueAvalancheChecksum verifica a difusão interna do checksum/MAC: mudar 1
// bit da mensagem autenticada deveria mudar ~50% dos bits dos 32 bytes de MAC.
type AtaqueAvalancheChecksum struct {
	mensagensPorCombinacao int
	tamanhoEntrada         int
	limiteMedia            float64
	limitePiorCaso         float64
}

// NovoAtaqueAvalancheChecksum cria o ataque. Sem argumento, usa
// mensagensPorCombinacao = 10, tamanhoEntrada = 32, limiteMedia = 0.4 e
// limitePiorCaso = 0.4.
func NovoAtaqueAvalancheChecksum(opcoes ...OpcoesAvalancheChecksum) *AtaqueAvalancheChecksum {
	o := OpcoesAvalancheChecksum{
		MensagensPorCombinacao: 10,
		TamanhoEntrada:         32,
		LimiteMedia:            0.4,
		LimitePiorCaso:         0.4,
	}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueAvalancheChecksum{
		mensagensPorCombinacao: o.MensagensPorCombinacao,
		tamanhoEntrada:         o.TamanhoEntrada,
		limiteMedia:            o.LimiteMedia,
		limitePiorCaso:         o.LimitePiorCaso,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueAvalancheChecksum) Nome() string {
	return "Efeito avalanche do checksum/MAC"
}

// Executar roda o ataque.
func (a *AtaqueAvalancheChecksum) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveMac := []byte(strings.Repeat("M", 32))

	primeiro := alvo.ChecksumBruto([]byte("teste"), chaveMac)
	tamanhoSaida := len(primeiro)

	somaGlobal := 0.0
	combinacoes := 0
	piorPosicao := -1
	piorBit := -1
	piorValor := 1.0

	for pos := 0; pos < a.tamanhoEntrada; pos++ {
		for bit := 0; bit < 8; bit++ {
			soma := 0.0
			for m := 0; m < a.mensagensPorCombinacao; m++ {
				entrada := seguranca.RandomBytes(a.tamanhoEntrada)
				alterada := append([]byte(nil), entrada...)
				alterada[pos] ^= byte(1 << bit)

				h1 := alvo.ChecksumBruto(entrada, chaveMac)
				h2 := alvo.ChecksumBruto(alterada, chaveMac)

				soma += float64(seguranca.BitsDiferentes(h1, h2)) / float64(tamanhoSaida*8)
			}
			media := soma / float64(a.mensagensPorCombinacao)

			somaGlobal += media
			combinacoes++
			if media < piorValor {
				piorPosicao = pos
				piorBit = bit
				piorValor = media
			}
		}
	}

	mediaGlobal := somaGlobal / float64(combinacoes)
	vulneravel := mediaGlobal < a.limiteMedia || piorValor < a.limitePiorCaso

	severidade := seguranca.SevInfo
	if vulneravel {
		if piorValor < 0.3 {
			severidade = seguranca.SevAlta
		} else {
			severidade = seguranca.SevMedia
		}
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"média global=%.1f%%; pior caso=%.1f%% na entrada[posição=%d, bit=%d] sobre %d bytes de MAC (limites: média>=%.0f%%, pior>=%.0f%%)",
			mediaGlobal*100, piorValor*100, piorPosicao, piorBit, tamanhoSaida,
			a.limiteMedia*100, a.limitePiorCaso*100,
		),
		Dados: map[string]any{
			"media_global": mediaGlobal,
			"pior": map[string]any{
				"posicao": piorPosicao,
				"bit":     piorBit,
				"valor":   piorValor,
			},
		},
	}, nil
}

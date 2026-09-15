package ataques

import (
	"encoding/hex"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueColisaoChecksum procura colisões no checksum via paradoxo do
// aniversário, tanto no checksum completo (32 bytes) quanto nos primeiros 4
// bytes (32 bits).
type AtaqueColisaoChecksum struct {
	amostras int
}

// NovoAtaqueColisaoChecksum cria o ataque. Sem argumento, usa amostras = 200000.
func NovoAtaqueColisaoChecksum(amostras ...int) *AtaqueColisaoChecksum {
	n := 200000
	if len(amostras) > 0 {
		n = amostras[0]
	}
	return &AtaqueColisaoChecksum{amostras: n}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueColisaoChecksum) Nome() string {
	return "Colisão no checksum (paradoxo do aniversário)"
}

// Executar roda o ataque.
func (a *AtaqueColisaoChecksum) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveDeMac := []byte(strings.Repeat("M", 32))

	vistosCompleto := map[string][]byte{}
	vistosTruncado := map[string][]byte{}
	var colisaoCompleta *[2][]byte
	var colisaoTruncada *[2][]byte

	for i := 0; i < a.amostras; i++ {
		mensagem := seguranca.RandomBytes(20)
		hash := alvo.ChecksumBruto(mensagem, chaveDeMac)

		if colisaoCompleta == nil {
			chaveHash := hex.EncodeToString(hash)
			if anterior, ok := vistosCompleto[chaveHash]; ok {
				colisaoCompleta = &[2][]byte{anterior, mensagem}
			} else {
				vistosCompleto[chaveHash] = mensagem
			}
		}

		if colisaoTruncada == nil {
			truncado := hex.EncodeToString(hash[:4])
			if anterior, ok := vistosTruncado[truncado]; ok {
				colisaoTruncada = &[2][]byte{anterior, mensagem}
			} else {
				vistosTruncado[truncado] = mensagem
			}
		}

		if colisaoCompleta != nil && colisaoTruncada != nil {
			break
		}
	}

	if colisaoCompleta != nil {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes: fmt.Sprintf(
				"COLISÃO COMPLETA encontrada em %d amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.",
				len(vistosCompleto),
			),
			Dados: map[string]any{
				"msg1_hex": hex.EncodeToString(colisaoCompleta[0]),
				"msg2_hex": hex.EncodeToString(colisaoCompleta[1]),
			},
		}, nil
	}

	var infoTruncada string
	if colisaoTruncada != nil {
		infoTruncada = fmt.Sprintf(
			"colisão de 32 bits encontrada em %d amostras (esperado pelo paradoxo do aniversário)",
			len(vistosTruncado),
		)
	} else {
		infoTruncada = fmt.Sprintf(
			"nenhuma colisão de 32 bits em %d amostras (um pouco abaixo do esperado, mas não conclusivo)",
			len(vistosTruncado),
		)
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes: fmt.Sprintf(
			"Nenhuma colisão completa em %d amostras (esperado). Nível truncado (32 bits): %s.",
			a.amostras, infoTruncada,
		),
		Dados: map[string]any{
			"amostras_completo": len(vistosCompleto),
			"amostras_truncado": len(vistosTruncado),
		},
	}, nil
}

package ataques

import (
	"encoding/hex"
	"fmt"

	"criptografia/internal/seguranca"
)

// AtaqueColisaoIV verifica se o mesmo IV aparece duas vezes com a mesma KEY.
type AtaqueColisaoIV struct {
	geracoes int
}

// NovoAtaqueColisaoIV cria o ataque. Sem argumento, usa geracoes = 5000.
func NovoAtaqueColisaoIV(geracoes ...int) *AtaqueColisaoIV {
	g := 5000
	if len(geracoes) > 0 {
		g = geracoes[0]
	}
	return &AtaqueColisaoIV{geracoes: g}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueColisaoIV) Nome() string {
	return "Colisão de IV"
}

// Executar roda o ataque.
func (a *AtaqueColisaoIV) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	vistos := map[string]bool{}
	colisoes := 0

	for i := 0; i < a.geracoes; i++ {
		token, err := alvo.Encrypt([]byte("MESMO_TEXTO_SEMPRE"))
		if err != nil {
			continue
		}
		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		iv := alvo.Decompor(decodificado).IV
		chaveIv := hex.EncodeToString(iv)
		if vistos[chaveIv] {
			colisoes++
		}
		vistos[chaveIv] = true
	}

	if colisoes > 0 {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   fmt.Sprintf("%d colisão(ões) de IV em %d gerações", colisoes, a.geracoes),
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("0 colisões em %d gerações", a.geracoes),
	}, nil
}

package ataques

import (
	"bytes"
	"encoding/hex"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueVetorDeterministico verifica que, com KEY e IV fixos, o keystream
// gerado é 100% determinístico.
type AtaqueVetorDeterministico struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueVetorDeterministico) Nome() string {
	return "Determinismo (vetor de referência key/iv fixos)"
}

// Executar roda o ataque.
func (a *AtaqueVetorDeterministico) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chaveFixa := []byte(strings.Repeat("K", len(alvo.ChaveDeTeste())))
	ivFixo := make([]byte, alvo.TamanhoIv())

	ks1 := alvo.GerarKeystreamBruto(chaveFixa, ivFixo, "enc", 32)
	ks2 := alvo.GerarKeystreamBruto(chaveFixa, ivFixo, "enc", 32)
	ks3 := alvo.GerarKeystreamBruto(chaveFixa, ivFixo, "enc", 32)

	deterministico := bytes.Equal(ks1, ks2) && bytes.Equal(ks2, ks3)

	if deterministico {
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: false,
			Severidade: seguranca.SevInfo,
			Detalhes: "Determinístico em 3 chamadas. Vetor de referência (key=64x\"K\", iv=zeros, prop=enc, 32 bytes): " +
				hex.EncodeToString(ks1),
			Dados: map[string]any{"vetor_hex": hex.EncodeToString(ks1)},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: true,
		Severidade: seguranca.SevCritica,
		Detalhes: "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: " +
			hex.EncodeToString(ks1) + " / " + hex.EncodeToString(ks2) + " / " + hex.EncodeToString(ks3),
		Dados: map[string]any{"vetor_hex": hex.EncodeToString(ks1)},
	}, nil
}

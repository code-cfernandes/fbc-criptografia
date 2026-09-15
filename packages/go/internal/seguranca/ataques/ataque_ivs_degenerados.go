package ataques

import (
	"bytes"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// AtaqueIVsDegenerados testa IVs especiais (tudo zero, tudo 0xFF, padrões
// alternados e crescente) que podem produzir saída degenerada mesmo quando a
// maioria das entradas se comporta bem.
type AtaqueIVsDegenerados struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueIVsDegenerados) Nome() string {
	return "IVs degenerados (zero, 0xFF, alternado)"
}

type casoIvDegenerado struct {
	nome string
	iv   []byte
}

// Executar roda o ataque.
func (a *AtaqueIVsDegenerados) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	tamanhoIv := alvo.TamanhoIv()
	tamanhoBloco := 32

	crescente := make([]byte, tamanhoIv)
	for i := 0; i < tamanhoIv; i++ {
		crescente[i] = byte(i)
	}

	casos := []casoIvDegenerado{
		{nome: "zero", iv: make([]byte, tamanhoIv)},
		{nome: "0xFF", iv: bytes.Repeat([]byte{0xff}, tamanhoIv)},
		{nome: "alternado 0xAA", iv: bytes.Repeat([]byte{0xaa}, tamanhoIv)},
		{nome: "alternado 0x55", iv: bytes.Repeat([]byte{0x55}, tamanhoIv)},
		{nome: "crescente", iv: crescente},
	}

	type problema struct {
		periodico   bool
		bytesUnicos int
	}
	problemas := map[string]problema{}
	nomesProblemas := []string{}

	for _, c := range casos {
		ks := alvo.GerarKeystreamBruto(chave, c.iv, "enc", tamanhoBloco)

		metade := tamanhoBloco / 2
		periodico := bytes.Equal(ks[:metade], ks[metade:metade+metade])

		unicos := map[byte]bool{}
		for _, b := range ks {
			unicos[b] = true
		}
		bytesUnicos := len(unicos)
		poucaVariedade := float64(bytesUnicos) < float64(tamanhoBloco)*0.5

		if periodico || poucaVariedade {
			problemas[c.nome] = problema{periodico: periodico, bytesUnicos: bytesUnicos}
			nomesProblemas = append(nomesProblemas, c.nome)
		}
	}

	if len(problemas) > 0 {
		partes := make([]string, len(nomesProblemas))
		dados := map[string]any{}
		for i, nome := range nomesProblemas {
			p := problemas[nome]
			simNao := "não"
			if p.periodico {
				simNao = "sim"
			}
			partes[i] = fmt.Sprintf("%s (periódico=%s, bytes únicos=%d/%d)", nome, simNao, p.bytesUnicos, tamanhoBloco)
			dados[nome] = map[string]any{"periodico": p.periodico, "bytes_unicos": p.bytesUnicos}
		}
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes:   strings.Join(partes, "; "),
			Dados:      dados,
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Nenhum dos %d IVs degenerados testados produziu saída anômala", len(casos)),
	}, nil
}

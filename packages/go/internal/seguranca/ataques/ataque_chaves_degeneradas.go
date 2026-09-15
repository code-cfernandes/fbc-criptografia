package ataques

import (
	"bytes"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesChavesDegeneradas configura o AtaqueChavesDegeneradas.
type OpcoesChavesDegeneradas struct {
	TamanhoBloco int
}

// AtaqueChavesDegeneradas testa chaves especiais (zero, 0xFF, alternadas,
// baixa entropia) com IV zerado, isolando a contribuição da chave.
type AtaqueChavesDegeneradas struct {
	tamanhoBloco int
}

// NovoAtaqueChavesDegeneradas cria o ataque. Sem argumento, usa
// tamanhoBloco = 32.
func NovoAtaqueChavesDegeneradas(opcoes ...OpcoesChavesDegeneradas) *AtaqueChavesDegeneradas {
	o := OpcoesChavesDegeneradas{TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueChavesDegeneradas{tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueChavesDegeneradas) Nome() string {
	return "Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)"
}

// Executar roda o ataque.
func (a *AtaqueChavesDegeneradas) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamChave := len(alvo.ChaveDeTeste())
	ivZero := make([]byte, alvo.TamanhoIv())

	seqCrescente := make([]byte, 512)
	for i := 0; i < 512; i++ {
		seqCrescente[i] = byte(i % 256)
	}

	type caso struct {
		nome  string
		chave []byte
	}
	casos := []caso{
		{nome: "zero", chave: make([]byte, tamChave)},
		{nome: "0xFF", chave: bytes.Repeat([]byte{0xff}, tamChave)},
		{nome: "alternada 0xAA", chave: bytes.Repeat([]byte{0xaa}, tamChave)},
		{nome: "alternada 0x55", chave: bytes.Repeat([]byte{0x55}, tamChave)},
		{nome: "repetida \"A\"", chave: bytes.Repeat([]byte{0x41}, tamChave)},
		{nome: "crescente", chave: seqCrescente[:tamChave]},
	}

	type problema struct {
		nome        string
		periodico   bool
		bytesUnicos int
	}
	problemas := []problema{}
	for _, c := range casos {
		ks := alvo.GerarKeystreamBruto(c.chave, ivZero, "enc", a.tamanhoBloco)

		metade := a.tamanhoBloco / 2
		periodico := bytes.Equal(ks[:metade], ks[metade:metade+metade])
		unicos := map[byte]bool{}
		for _, b := range ks {
			unicos[b] = true
		}
		bytesUnicos := len(unicos)

		if periodico || float64(bytesUnicos) < float64(a.tamanhoBloco)*0.5 {
			problemas = append(problemas, problema{nome: c.nome, periodico: periodico, bytesUnicos: bytesUnicos})
		}
	}

	if len(problemas) > 0 {
		partes := make([]string, len(problemas))
		for i, p := range problemas {
			simNao := "não"
			if p.periodico {
				simNao = "sim"
			}
			partes[i] = fmt.Sprintf("%s (periódico=%s, bytes únicos=%d/%d)", p.nome, simNao, p.bytesUnicos, a.tamanhoBloco)
		}
		dados := map[string]any{}
		for _, p := range problemas {
			dados[p.nome] = map[string]any{"periodico": p.periodico, "bytes_unicos": p.bytesUnicos}
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
		Detalhes:   fmt.Sprintf("Nenhuma das %d chaves degeneradas testadas produziu saída anômala", len(casos)),
	}, nil
}

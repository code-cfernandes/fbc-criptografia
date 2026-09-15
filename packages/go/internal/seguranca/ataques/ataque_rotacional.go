package ataques

import (
	"bytes"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesRotacional configura o AtaqueRotacional.
type OpcoesRotacional struct {
	Tamanho int
}

// AtaqueRotacional testa se a cifra é simétrica a deslocamentos circulares de
// key/iv: keystream(rot(key), rot(iv)) seria uma rotação de keystream(key, iv).
type AtaqueRotacional struct {
	tamanho int
}

// NovoAtaqueRotacional cria o ataque. Sem argumento, usa tamanho = 64.
func NovoAtaqueRotacional(opcoes ...OpcoesRotacional) *AtaqueRotacional {
	o := OpcoesRotacional{Tamanho: 64}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueRotacional{tamanho: o.Tamanho}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueRotacional) Nome() string {
	return "Rotacional/slide (simetria por rotação)"
}

// rotacionar desloca circularmente um buffer k posições.
func rotacionar(buf []byte, k int) []byte {
	n := len(buf)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = buf[(i+k)%n]
	}
	return out
}

// Executar roda o ataque.
func (a *AtaqueRotacional) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	iv := seguranca.RandomBytes(alvo.TamanhoIv())
	ks1 := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanho)

	coincidencias := []string{}
	for k := 1; k < len(chave); k++ {
		ks2 := alvo.GerarKeystreamBruto(rotacionar(chave, k), rotacionar(iv, k), "enc", a.tamanho)

		if bytes.Equal(ks2, ks1) {
			coincidencias = append(coincidencias, fmt.Sprintf("rotação %d: keystream idêntico", k))
			continue
		}
		alvoRot := rotacionar(ks1[:32], k)
		if bytes.Equal(ks2[:32], alvoRot) {
			coincidencias = append(coincidencias, fmt.Sprintf("rotação %d: keystream rotacionado", k))
		}
	}

	vulneravel := len(coincidencias) > 0
	severidade := seguranca.SevInfo
	detalhes := fmt.Sprintf("Nenhuma das %d rotações de byte reproduziu o keystream", len(chave)-1)
	if vulneravel {
		severidade = seguranca.SevCritica
		detalhes = "Simetria rotacional encontrada: " + strings.Join(coincidencias[:min(5, len(coincidencias))], "; ")
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados:      map[string]any{"coincidencias": coincidencias},
	}, nil
}

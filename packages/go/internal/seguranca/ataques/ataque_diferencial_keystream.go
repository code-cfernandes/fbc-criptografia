package ataques

import (
	"encoding/hex"
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesDiferencialKeystream configura o AtaqueDiferencialKeystream.
type OpcoesDiferencialKeystream struct {
	Amostras     int
	TamanhoBloco int
}

// AtaqueDiferencialKeystream faz criptanálise diferencial no keystream com uma
// diferença FIXA (1 bit) no IV.
type AtaqueDiferencialKeystream struct {
	amostras     int
	tamanhoBloco int
}

// NovoAtaqueDiferencialKeystream cria o ataque. Sem argumento, usa
// amostras = 2000 e tamanhoBloco = 32.
func NovoAtaqueDiferencialKeystream(opcoes ...OpcoesDiferencialKeystream) *AtaqueDiferencialKeystream {
	o := OpcoesDiferencialKeystream{Amostras: 2000, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueDiferencialKeystream{amostras: o.Amostras, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueDiferencialKeystream) Nome() string {
	return "Diferencial do keystream (delta fixo no IV)"
}

// Executar roda o ataque.
func (a *AtaqueDiferencialKeystream) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := seguranca.RandomBytes(len(alvo.ChaveDeTeste()))
	tamanhoIv := alvo.TamanhoIv()

	delta := make([]byte, tamanhoIv)
	delta[seguranca.RandomInt(0, tamanhoIv-1)] = byte(1 << seguranca.RandomInt(0, 7))

	totalBits := a.tamanhoBloco * 8
	sempreZero := make([]bool, totalBits)
	sempreUm := make([]bool, totalBits)
	for i := range sempreZero {
		sempreZero[i] = true
		sempreUm[i] = true
	}
	deltas := map[string]bool{}

	for i := 0; i < a.amostras; i++ {
		iv := seguranca.RandomBytes(tamanhoIv)
		iv2 := a.xorBytes(iv, delta)

		ks1 := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanhoBloco)
		ks2 := alvo.GerarKeystreamBruto(chave, iv2, "enc", a.tamanhoBloco)
		d := a.xorBytes(ks1, ks2)
		deltas[hex.EncodeToString(d)] = true

		for p := 0; p < len(d); p++ {
			by := d[p]
			for b := 0; b < 8; b++ {
				idx := p*8 + b
				if ((by >> b) & 1) == 1 {
					sempreZero[idx] = false
				} else {
					sempreUm[idx] = false
				}
			}
		}
	}

	bitsFixos := 0
	for idx := 0; idx < totalBits; idx++ {
		if sempreZero[idx] || sempreUm[idx] {
			bitsFixos++
		}
	}
	colisoes := a.amostras - len(deltas)

	vulneravel := bitsFixos > 0 || colisoes > 0
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"delta de 1 bit no IV: %d bit(s) de saída fixo(s), %d diferencial(is) repetido(s) em %d amostras",
			bitsFixos, colisoes, a.amostras,
		),
		Dados: map[string]any{"bits_fixos": bitsFixos, "colisoes": colisoes},
	}, nil
}

// xorBytes faz XOR byte a byte de dois buffers.
func (a *AtaqueDiferencialKeystream) xorBytes(a2, b []byte) []byte {
	out := make([]byte, len(a2))
	for i := 0; i < len(a2); i++ {
		out[i] = a2[i] ^ b[i]
	}
	return out
}

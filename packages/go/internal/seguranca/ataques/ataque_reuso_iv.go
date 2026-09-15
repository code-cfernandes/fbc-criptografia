package ataques

import (
	"bytes"
	"encoding/hex"

	"criptografia/internal/seguranca"
)

// AtaqueReusoIV simula o que aconteceria SE o IV fosse reusado, provando
// matematicamente o quanto vaza nesse cenário catastrófico (two-time pad).
type AtaqueReusoIV struct{}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueReusoIV) Nome() string {
	return "Reuso forçado de IV (two-time pad)"
}

// Executar roda o ataque.
func (a *AtaqueReusoIV) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := alvo.ChaveDeTeste()
	ivFixo := seguranca.RandomBytes(alvo.TamanhoIv())

	plaintext1 := []byte("TRANSFERIR_1000")
	plaintext2 := []byte("CANCELAR_TUDO!!")
	tamanho := max(len(plaintext1), len(plaintext2))

	keystream := alvo.GerarKeystreamBruto([]byte(chave), ivFixo, "enc", tamanho)

	ciphertext1 := a.xor(plaintext1, keystream)
	ciphertext2 := a.xor(plaintext2, keystream)

	xorDosCiphertexts := a.xor(ciphertext1, ciphertext2)
	xorEsperadoDosPlaintexts := a.xor(plaintext1, plaintext2)

	vazou := bytes.Equal(xorDosCiphertexts, xorEsperadoDosPlaintexts)

	severidade := seguranca.SevAlta
	detalhes := "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)"
	if vazou {
		severidade = seguranca.SevDemonstracao
		detalhes = "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) " +
			"sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA " +
			"defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: !vazou,
		Severidade: severidade,
		Detalhes:   detalhes,
		Dados: map[string]any{
			"plaintext1":          string(plaintext1),
			"plaintext2":          string(plaintext2),
			"xor_plaintexts_hex":  hex.EncodeToString(xorEsperadoDosPlaintexts),
			"xor_ciphertexts_hex": hex.EncodeToString(xorDosCiphertexts),
		},
	}, nil
}

// xor faz XOR byte a byte de dois buffers.
func (a *AtaqueReusoIV) xor(a2, b []byte) []byte {
	n := min(len(a2), len(b))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a2[i] ^ b[i]
	}
	return out
}

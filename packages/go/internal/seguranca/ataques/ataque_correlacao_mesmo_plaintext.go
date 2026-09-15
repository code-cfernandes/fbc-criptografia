package ataques

import (
	"encoding/hex"
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesCorrelacaoMesmoPlaintext configura o AtaqueCorrelacaoMesmoPlaintext.
type OpcoesCorrelacaoMesmoPlaintext struct {
	Amostras  int
	TextoFixo string
}

// AtaqueCorrelacaoMesmoPlaintext verifica se ciphertexts do mesmo plaintext se
// comportam como se fossem de textos diferentes (distância de Hamming ~50%).
type AtaqueCorrelacaoMesmoPlaintext struct {
	amostras  int
	textoFixo string
}

// NovoAtaqueCorrelacaoMesmoPlaintext cria o ataque. Sem argumento, usa
// amostras = 300 e textoFixo = "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR".
func NovoAtaqueCorrelacaoMesmoPlaintext(opcoes ...OpcoesCorrelacaoMesmoPlaintext) *AtaqueCorrelacaoMesmoPlaintext {
	o := OpcoesCorrelacaoMesmoPlaintext{Amostras: 300, TextoFixo: "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR"}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCorrelacaoMesmoPlaintext{amostras: o.Amostras, textoFixo: o.TextoFixo}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCorrelacaoMesmoPlaintext) Nome() string {
	return "Correlação entre ciphertexts do mesmo plaintext"
}

// Executar roda o ataque.
func (a *AtaqueCorrelacaoMesmoPlaintext) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	ciphertexts := make([][]byte, 0, a.amostras)
	for i := 0; i < a.amostras; i++ {
		token, err := alvo.Encrypt([]byte(a.textoFixo))
		if err != nil {
			continue
		}
		decodificado, err := alvo.Base64urlDecode(token[len(alvo.Prefixo()):])
		if err != nil {
			continue
		}
		ciphertexts = append(ciphertexts, alvo.Decompor(decodificado).Ciphertext)
	}

	comparacoes := min(500, (len(ciphertexts)*(len(ciphertexts)-1))/2)
	distancias := make([]float64, 0, comparacoes)
	for c := 0; c < comparacoes; c++ {
		i := seguranca.RandomInt(0, len(ciphertexts)-1)
		j := seguranca.RandomInt(0, len(ciphertexts)-1)
		if i == j {
			continue
		}
		distancias = append(distancias, a.distanciaHammingRelativa(ciphertexts[i], ciphertexts[j]))
	}

	media := 0.0
	for _, v := range distancias {
		media += v
	}
	if len(distancias) > 0 {
		media /= float64(len(distancias))
	}

	unicos := map[string]bool{}
	for _, b := range ciphertexts {
		unicos[hex.EncodeToString(b)] = true
	}
	duplicatas := len(ciphertexts) - len(unicos)

	vulneravel := media < 0.4 || media > 0.6 || duplicatas > 0
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevAlta
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"distância de Hamming média entre ciphertexts do mesmo texto: %.1f%% (esperado ~50%%), %d duplicata(s) exata(s) em %d amostras",
			media*100, duplicatas, a.amostras,
		),
		Dados: map[string]any{"media": media, "duplicatas": duplicatas},
	}, nil
}

// distanciaHammingRelativa calcula a fração de bits diferentes entre dois buffers.
func (a *AtaqueCorrelacaoMesmoPlaintext) distanciaHammingRelativa(a2, b []byte) float64 {
	length := min(len(a2), len(b))
	if length == 0 {
		return 0.5
	}
	diff := 0
	for i := 0; i < length; i++ {
		diff += seguranca.ContarBits1(a2[i] ^ b[i])
	}
	return float64(diff) / float64(length*8)
}

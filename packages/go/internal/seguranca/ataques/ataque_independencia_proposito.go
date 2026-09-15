package ataques

import (
	"encoding/hex"
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesIndependenciaProposito configura o AtaqueIndependenciaProposito.
type OpcoesIndependenciaProposito struct {
	Amostras int
	Tamanho  int
}

// AtaqueIndependenciaProposito verifica se os keystreams de propósitos
// diferentes ('enc' e 'mac') derivados da mesma (key, iv) são independentes.
// Se não forem, recuperar o keystream de dados permite derivar a chave do MAC
// e forjar tokens válidos.
type AtaqueIndependenciaProposito struct {
	amostras int
	tamanho  int
}

// NovoAtaqueIndependenciaProposito cria o ataque. Sem argumento, usa
// amostras = 2000 e tamanho = 32.
func NovoAtaqueIndependenciaProposito(opcoes ...OpcoesIndependenciaProposito) *AtaqueIndependenciaProposito {
	o := OpcoesIndependenciaProposito{Amostras: 2000, Tamanho: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueIndependenciaProposito{amostras: o.Amostras, tamanho: o.Tamanho}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueIndependenciaProposito) Nome() string {
	return "Independência entre keystreams de propósitos diferentes (enc x mac)"
}

// Executar roda o ataque.
func (a *AtaqueIndependenciaProposito) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamChave := len(alvo.ChaveDeTeste())

	distancias := make([]float64, 0, a.amostras)
	mascaras := map[string]bool{}

	for i := 0; i < a.amostras; i++ {
		chave := seguranca.RandomBytes(tamChave)
		iv := seguranca.RandomBytes(alvo.TamanhoIv())

		enc := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanho)
		mac := alvo.GerarKeystreamBruto(chave, iv, "mac", a.tamanho)

		distancias = append(distancias, float64(seguranca.BitsDiferentes(enc, mac))/float64(a.tamanho*8))
		mascaras[hex.EncodeToString(a.xorBytes(enc, mac))] = true
	}

	media := 0.0
	for _, v := range distancias {
		media += v
	}
	media /= float64(len(distancias))
	mascarasDistintas := len(mascaras)

	vulneravel := media < 0.4 || media > 0.6 || mascarasDistintas < a.amostras
	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevCritica
	}

	sufixo := ""
	if mascarasDistintas < a.amostras {
		sufixo = " - MÁSCARA REPETIDA: mac previsível a partir de enc!"
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"Hamming médio enc x mac=%.1f%% (esperado ~50%%); %d máscara(s) XOR distinta(s) em %d amostras%s",
			media*100, mascarasDistintas, a.amostras, sufixo,
		),
		Dados: map[string]any{"media": media, "mascaras_distintas": mascarasDistintas},
	}, nil
}

// xorBytes faz XOR byte a byte de dois buffers.
func (a *AtaqueIndependenciaProposito) xorBytes(a2, b []byte) []byte {
	n := min(len(a2), len(b))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a2[i] ^ b[i]
	}
	return out
}

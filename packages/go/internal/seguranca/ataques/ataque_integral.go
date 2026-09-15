package ataques

import (
	"fmt"
	"math"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesIntegral configura o AtaqueIntegral.
type OpcoesIntegral struct {
	TamanhoBloco  int
	PosicoesIv    int
	PosicoesChave int
	Tentativas    int
	LimiteZ       float64
}

// AtaqueIntegral (square) fixa a chave e percorre todos os 256 valores de um
// byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes. Numa
// função aleatória cada byte da soma é zero com probabilidade 1/256; difusão
// incompleta deixa a soma tender a zero muito mais que o acaso.
type AtaqueIntegral struct {
	tamanhoBloco  int
	posicoesIv    int
	posicoesChave int
	tentativas    int
	limiteZ       float64
}

// NovoAtaqueIntegral cria o ataque. Sem argumento, usa tamanhoBloco = 32,
// posicoesIv = 8, posicoesChave = 8, tentativas = 16 e limiteZ = 5.0.
func NovoAtaqueIntegral(opcoes ...OpcoesIntegral) *AtaqueIntegral {
	o := OpcoesIntegral{
		TamanhoBloco:  32,
		PosicoesIv:    8,
		PosicoesChave: 8,
		Tentativas:    16,
		LimiteZ:       5.0,
	}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueIntegral{
		tamanhoBloco:  o.TamanhoBloco,
		posicoesIv:    o.PosicoesIv,
		posicoesChave: o.PosicoesChave,
		tentativas:    o.Tentativas,
		limiteZ:       o.LimiteZ,
	}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueIntegral) Nome() string {
	return "Integral (soma balanceada variando 1 byte de IV/chave)"
}

// Executar roda o ataque.
func (a *AtaqueIntegral) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamIv := alvo.TamanhoIv()
	tamChave := len(alvo.ChaveDeTeste())

	distinguidores := []string{}
	zerosTotal := 0
	bytesTotal := 0

	for t := 0; t < a.tentativas; t++ {
		chave := seguranca.RandomBytes(tamChave)
		ivBase := seguranca.RandomBytes(tamIv)

		for pos := 0; pos < min(a.posicoesIv, tamIv); pos++ {
			xor, zeros := a.somarVariando(alvo, chave, ivBase, "iv", pos)
			zerosTotal += zeros
			bytesTotal += a.tamanhoBloco
			if a.todosZeros(xor) {
				distinguidores = append(distinguidores, fmt.Sprintf("iv[%d]", pos))
			}
		}

		for pos := 0; pos < min(a.posicoesChave, tamChave); pos++ {
			xor, zeros := a.somarVariando(alvo, chave, ivBase, "key", pos)
			zerosTotal += zeros
			bytesTotal += a.tamanhoBloco
			if a.todosZeros(xor) {
				distinguidores = append(distinguidores, fmt.Sprintf("key[%d]", pos))
			}
		}
	}

	p := 1.0 / 256.0
	esperado := float64(bytesTotal) * p
	desvio := math.Sqrt(float64(bytesTotal) * p * (1 - p))
	z := 0.0
	if desvio > 0 {
		z = (float64(zerosTotal) - esperado) / desvio
	}

	vulneravel := len(distinguidores) > 0 || z > a.limiteZ

	if len(distinguidores) > 0 {
		limite := min(10, len(distinguidores))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   "Soma balanceada (XOR zero) encontrada variando: " + strings.Join(distinguidores[:limite], ", "),
			Dados:      map[string]any{"distinguidores": distinguidores},
		}, nil
	}

	severidade := seguranca.SevInfo
	if vulneravel {
		severidade = seguranca.SevMedia
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: vulneravel,
		Severidade: severidade,
		Detalhes: fmt.Sprintf(
			"bytes de saída zerados=%d (esperado ~%.1f, z=%.2f) em %d amostras; limite z=%.1f",
			zerosTotal, esperado, z, bytesTotal, a.limiteZ,
		),
		Dados: map[string]any{"zeros": zerosTotal, "esperado": esperado, "z": z},
	}, nil
}

// somarVariando devolve o XOR de 256 keystreams e quantos bytes deram zero.
func (a *AtaqueIntegral) somarVariando(alvo seguranca.AlvoCriptografico, chave, ivBase []byte, campo string, pos int) ([]byte, int) {
	xor := make([]byte, a.tamanhoBloco)
	for v := 0; v < 256; v++ {
		k := append([]byte(nil), chave...)
		iv := append([]byte(nil), ivBase...)
		if campo == "iv" {
			iv[pos] = byte(v)
		} else {
			k[pos] = byte(v)
		}
		ks := alvo.GerarKeystreamBruto(k, iv, "enc", a.tamanhoBloco)
		xor = a.xorBytes(xor, ks)
	}

	zeros := 0
	for _, b := range xor {
		if b == 0 {
			zeros++
		}
	}
	return xor, zeros
}

// todosZeros informa se o buffer é todo de zeros.
func (a *AtaqueIntegral) todosZeros(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

// xorBytes faz XOR byte a byte de dois buffers.
func (a *AtaqueIntegral) xorBytes(a2, b []byte) []byte {
	out := make([]byte, len(a2))
	for i := 0; i < len(a2); i++ {
		out[i] = a2[i] ^ b[i]
	}
	return out
}

package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesCoberturaDependencia configura o AtaqueCoberturaDependencia.
type OpcoesCoberturaDependencia struct {
	TamanhoBloco       int
	PerturbacoesPorPar int
}

// AtaqueCoberturaDependencia verifica, byte a byte, se toda posição de SAÍDA
// depende de toda posição de ENTRADA da chave.
type AtaqueCoberturaDependencia struct {
	tamanhoBloco       int
	perturbacoesPorPar int
}

// NovoAtaqueCoberturaDependencia cria o ataque. Sem argumento, usa
// tamanhoBloco = 32 e perturbacoesPorPar = 5.
func NovoAtaqueCoberturaDependencia(opcoes ...OpcoesCoberturaDependencia) *AtaqueCoberturaDependencia {
	o := OpcoesCoberturaDependencia{TamanhoBloco: 32, PerturbacoesPorPar: 5}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCoberturaDependencia{tamanhoBloco: o.TamanhoBloco, perturbacoesPorPar: o.PerturbacoesPorPar}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCoberturaDependencia) Nome() string {
	return "Cobertura de dependência (matriz entrada x saída)"
}

// Executar roda o ataque.
func (a *AtaqueCoberturaDependencia) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	tamanho := a.tamanhoBloco
	chaveBase := make([]byte, tamanho)
	iv := seguranca.RandomBytes(alvo.TamanhoIv())

	ksBase := alvo.GerarKeystreamBruto(chaveBase, iv, "enc", tamanho)

	paresIndependentes := []string{}

	for posEntrada := 0; posEntrada < tamanho; posEntrada++ {
		afetouAlgumaSaida := make([]bool, tamanho)

		for p := 0; p < a.perturbacoesPorPar; p++ {
			chaveTeste := append([]byte(nil), chaveBase...)
			chaveTeste[posEntrada] = byte(seguranca.RandomInt(1, 255))
			ks := alvo.GerarKeystreamBruto(chaveTeste, iv, "enc", tamanho)

			for posSaida := 0; posSaida < tamanho; posSaida++ {
				if ks[posSaida] != ksBase[posSaida] {
					afetouAlgumaSaida[posSaida] = true
				}
			}
		}

		for posSaida := 0; posSaida < tamanho; posSaida++ {
			if !afetouAlgumaSaida[posSaida] {
				paresIndependentes = append(paresIndependentes, fmt.Sprintf("entrada[%d] -> saída[%d]", posEntrada, posSaida))
			}
		}
	}

	if len(paresIndependentes) > 0 {
		limite := min(20, len(paresIndependentes))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevMedia,
			Detalhes: fmt.Sprintf(
				"%d par(es) sem dependência detectável em %d tentativas cada",
				len(paresIndependentes), a.perturbacoesPorPar,
			),
			Dados: map[string]any{"pares": paresIndependentes[:limite]},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todos os %d pares (entrada, saída) mostraram dependência", tamanho*tamanho),
	}, nil
}

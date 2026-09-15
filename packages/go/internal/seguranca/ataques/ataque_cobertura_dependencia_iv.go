package ataques

import (
	"fmt"

	"criptografia/internal/seguranca"
)

// OpcoesCoberturaDependenciaIV configura o AtaqueCoberturaDependenciaIV.
type OpcoesCoberturaDependenciaIV struct {
	TamanhoBloco           int
	PerturbacoesPorPosicao int
}

// AtaqueCoberturaDependenciaIV é o complemento do AtaqueCoberturaDependencia:
// aqui varia o IV, verificando se toda posição do IV influencia toda posição
// de saída.
type AtaqueCoberturaDependenciaIV struct {
	tamanhoBloco           int
	perturbacoesPorPosicao int
}

// NovoAtaqueCoberturaDependenciaIV cria o ataque. Sem argumento, usa
// tamanhoBloco = 32 e perturbacoesPorPosicao = 5.
func NovoAtaqueCoberturaDependenciaIV(opcoes ...OpcoesCoberturaDependenciaIV) *AtaqueCoberturaDependenciaIV {
	o := OpcoesCoberturaDependenciaIV{TamanhoBloco: 32, PerturbacoesPorPosicao: 5}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueCoberturaDependenciaIV{tamanhoBloco: o.TamanhoBloco, perturbacoesPorPosicao: o.PerturbacoesPorPosicao}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueCoberturaDependenciaIV) Nome() string {
	return "Cobertura de dependência do IV (entrada x saída)"
}

// Executar roda o ataque.
func (a *AtaqueCoberturaDependenciaIV) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())
	tamanhoIv := alvo.TamanhoIv()
	ivBase := make([]byte, tamanhoIv)

	ksBase := alvo.GerarKeystreamBruto(chave, ivBase, "enc", a.tamanhoBloco)

	paresIndependentes := []string{}

	for posIv := 0; posIv < tamanhoIv; posIv++ {
		afetou := make([]bool, a.tamanhoBloco)

		for p := 0; p < a.perturbacoesPorPosicao; p++ {
			iv := append([]byte(nil), ivBase...)
			iv[posIv] = byte(seguranca.RandomInt(1, 255))
			ks := alvo.GerarKeystreamBruto(chave, iv, "enc", a.tamanhoBloco)

			for posSaida := 0; posSaida < a.tamanhoBloco; posSaida++ {
				if ks[posSaida] != ksBase[posSaida] {
					afetou[posSaida] = true
				}
			}
		}

		for posSaida := 0; posSaida < a.tamanhoBloco; posSaida++ {
			if !afetou[posSaida] {
				paresIndependentes = append(paresIndependentes, fmt.Sprintf("iv[%d] -> saida[%d]", posIv, posSaida))
			}
		}
	}

	if len(paresIndependentes) > 0 {
		limite := min(20, len(paresIndependentes))
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevAlta,
			Detalhes: fmt.Sprintf(
				"%d par(es) sem dependência detectável em %d tentativas cada",
				len(paresIndependentes), a.perturbacoesPorPosicao,
			),
			Dados: map[string]any{"pares": paresIndependentes[:limite]},
		}, nil
	}

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   fmt.Sprintf("Todas as %d posições do IV influenciam todas as %d posições de saída", tamanhoIv, a.tamanhoBloco),
	}, nil
}

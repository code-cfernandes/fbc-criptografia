package ataques

import (
	"bytes"
	"fmt"
	"strings"

	"criptografia/internal/seguranca"
)

// OpcoesFoldEstrutural configura o AtaqueFoldEstrutural.
type OpcoesFoldEstrutural struct {
	Amostras     int
	TamanhoBloco int
}

// AtaqueFoldEstrutural testa repetição em frações de 1/2, 1/4 e 1/8 do bloco
// do keystream.
type AtaqueFoldEstrutural struct {
	amostras     int
	tamanhoBloco int
}

// NovoAtaqueFoldEstrutural cria o ataque. Sem argumento, usa amostras = 5000 e
// tamanhoBloco = 32.
func NovoAtaqueFoldEstrutural(opcoes ...OpcoesFoldEstrutural) *AtaqueFoldEstrutural {
	o := OpcoesFoldEstrutural{Amostras: 5000, TamanhoBloco: 32}
	if len(opcoes) > 0 {
		o = opcoes[0]
	}
	return &AtaqueFoldEstrutural{amostras: o.Amostras, tamanhoBloco: o.TamanhoBloco}
}

// Nome devolve o nome exibido no relatório.
func (a *AtaqueFoldEstrutural) Nome() string {
	return "Fold estrutural (metades/quartos/oitavos repetidos)"
}

// Executar roda o ataque.
func (a *AtaqueFoldEstrutural) Executar(alvo seguranca.AlvoCriptografico) (seguranca.ResultadoAtaque, error) {
	chave := []byte(alvo.ChaveDeTeste())

	divisores := []int{}
	for _, d := range []int{2, 4, 8, 16} {
		if a.tamanhoBloco%d == 0 && a.tamanhoBloco/d >= 1 {
			divisores = append(divisores, d)
		}
	}

	ocorrencias := map[int]int{}
	for _, d := range divisores {
		ocorrencias[d] = 0
	}

	for i := 0; i < a.amostras; i++ {
		ks := alvo.GerarKeystreamBruto(chave, seguranca.RandomBytes(alvo.TamanhoIv()), "enc", a.tamanhoBloco)
		for _, divisor := range divisores {
			tamFatia := a.tamanhoBloco / divisor
			primeiraFatia := ks[:tamFatia]
			for j := 1; j < divisor; j++ {
				if bytes.Equal(ks[j*tamFatia:j*tamFatia+tamFatia], primeiraFatia) {
					ocorrencias[divisor]++
					break
				}
			}
		}
	}

	margem := func(divisor int) int {
		if a.tamanhoBloco/divisor <= 2 {
			return int(float64(a.amostras)*0.01) + 3
		}
		return 5
	}

	problemas := map[int]int{}
	for _, divisor := range divisores {
		if ocorrencias[divisor] > margem(divisor) {
			problemas[divisor] = ocorrencias[divisor]
		}
	}

	if len(problemas) > 0 {
		partes := make([]string, 0, len(problemas))
		for _, divisor := range divisores {
			if c, ok := problemas[divisor]; ok {
				partes = append(partes, fmt.Sprintf("1/%d do bloco repetido em %d/%d", divisor, c, a.amostras))
			}
		}
		dados := map[string]any{}
		for _, divisor := range divisores {
			dados[fmt.Sprint(divisor)] = ocorrencias[divisor]
		}
		return seguranca.ResultadoAtaque{
			NomeAtaque: a.Nome(),
			Vulneravel: true,
			Severidade: seguranca.SevCritica,
			Detalhes:   strings.Join(partes, ", "),
			Dados:      dados,
		}, nil
	}

	jsonOcorrencias := "{"
	for i, divisor := range divisores {
		if i > 0 {
			jsonOcorrencias += ","
		}
		jsonOcorrencias += fmt.Sprintf("\"%d\":%d", divisor, ocorrencias[divisor])
	}
	jsonOcorrencias += "}"

	return seguranca.ResultadoAtaque{
		NomeAtaque: a.Nome(),
		Vulneravel: false,
		Severidade: seguranca.SevInfo,
		Detalhes:   "Nenhuma repetição estrutural acima do ruído esperado: " + jsonOcorrencias,
	}, nil
}

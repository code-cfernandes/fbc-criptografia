package seguranca

import (
	"errors"
	"fmt"
	"strings"
)

// SuiteDeAtaques orquestra a execução de uma coleção de ataques contra um alvo.
type SuiteDeAtaques struct {
	ataques []Ataque
}

// Adicionar registra um ataque na suíte.
func (s *SuiteDeAtaques) Adicionar(ataque Ataque) *SuiteDeAtaques {
	s.ataques = append(s.ataques, ataque)
	return s
}

// Rodar executa todos os ataques e devolve os resultados.
func (s *SuiteDeAtaques) Rodar(alvo AlvoCriptografico) []ResultadoAtaque {
	resultados := make([]ResultadoAtaque, 0, len(s.ataques))

	for _, ataque := range s.ataques {
		res, err := ataque.Executar(alvo)
		if err != nil {
			var skip *SkipAtaqueException
			if errors.As(err, &skip) {
				resultados = append(resultados, ResultadoAtaque{
					NomeAtaque: ataque.Nome(),
					Vulneravel: false,
					Severidade: SevPulado,
					Detalhes:   "Pulado: " + err.Error(),
				})
			} else {
				resultados = append(resultados, ResultadoAtaque{
					NomeAtaque: ataque.Nome(),
					Vulneravel: true,
					Severidade: SevErro,
					Detalhes:   "Erro ao executar: " + err.Error(),
				})
			}
			continue
		}
		resultados = append(resultados, res)
	}

	return resultados
}

// RodarEImprimir roda e imprime um relatório. Devolve true se nenhuma
// vulnerabilidade foi encontrada.
func (s *SuiteDeAtaques) RodarEImprimir(alvo AlvoCriptografico) bool {
	resultados := s.Rodar(alvo)
	vulnerabilidades := 0

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("RELATÓRIO DA SUÍTE DE ATAQUES")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	for _, r := range resultados {
		fmt.Println(r.LinhaResumo())
		if r.Vulneravel && r.Severidade != SevPulado && r.Severidade != SevDemonstracao {
			vulnerabilidades++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	if vulnerabilidades == 0 {
		fmt.Printf("RESUMO: nenhuma vulnerabilidade encontrada em %d ataque(s).\n", len(resultados))
	} else {
		fmt.Printf("RESUMO: %d vulnerabilidade(s) encontrada(s) de %d ataque(s) rodados!\n", vulnerabilidades, len(resultados))
	}
	fmt.Println(strings.Repeat("=", 70))

	return vulnerabilidades == 0
}

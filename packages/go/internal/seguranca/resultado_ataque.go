package seguranca

import "fmt"

// Severidade classifica o resultado de um ataque.
type Severidade string

const (
	SevCritica      Severidade = "critica"
	SevAlta         Severidade = "alta"
	SevMedia        Severidade = "media"
	SevBaixa        Severidade = "baixa"
	SevInfo         Severidade = "info"
	SevPulado       Severidade = "pulado"
	SevDemonstracao Severidade = "demonstracao"
	SevErro         Severidade = "erro"
)

// ResultadoAtaque é o resultado de rodar um ataque contra um alvo.
//
// Vulneravel = true significa que o ataque ACHOU um problema (a cifra falhou).
// Vulneravel = false significa que a cifra resistiu a esse ataque específico.
type ResultadoAtaque struct {
	NomeAtaque string
	Vulneravel bool
	Severidade Severidade
	Detalhes   string
	Dados      map[string]any
}

// LinhaResumo formata o resultado para o relatório da suíte.
func (r ResultadoAtaque) LinhaResumo() string {
	var status string
	switch r.Severidade {
	case SevPulado:
		status = "PULADO"
	case SevDemonstracao:
		status = "DEMONSTRAÇÃO"
	default:
		if r.Vulneravel {
			status = "❌ VULNERÁVEL"
		} else {
			status = "✅ resistiu"
		}
	}

	return fmt.Sprintf("[%s] %s (%s): %s", status, r.NomeAtaque, r.Severidade, r.Detalhes)
}

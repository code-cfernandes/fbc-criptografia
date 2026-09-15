package seguranca

// SkipAtaqueException é devolvida quando o alvo não suporta os recursos que um
// ataque precisa. A suíte marca o ataque como "pulado" em vez de falhar.
type SkipAtaqueException struct {
	Msg string
}

// Error implementa a interface error.
func (e *SkipAtaqueException) Error() string {
	return e.Msg
}

// NovoSkip cria uma SkipAtaqueException.
func NovoSkip(msg string) error {
	return &SkipAtaqueException{Msg: msg}
}

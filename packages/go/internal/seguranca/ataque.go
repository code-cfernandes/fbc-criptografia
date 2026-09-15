package seguranca

// Ataque é o contrato dos ataques da suíte.
type Ataque interface {
	Nome() string

	// Executar roda o ataque contra o alvo e devolve o resultado.
	// Deve devolver um *SkipAtaqueException se o alvo não suportar os recursos
	// necessários (ex: não expõe GerarKeystreamBruto).
	Executar(alvo AlvoCriptografico) (ResultadoAtaque, error)
}

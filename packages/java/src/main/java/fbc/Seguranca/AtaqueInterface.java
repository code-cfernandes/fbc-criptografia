package fbc.Seguranca;

public interface AtaqueInterface {
    String nome();

    /**
     * Roda o ataque contra o alvo e retorna o resultado.
     * Deve lançar {@link SkipAtaqueException} se o alvo não suportar os recursos
     * necessários.
     */
    ResultadoAtaque executar(AlvoCriptografico alvo);
}

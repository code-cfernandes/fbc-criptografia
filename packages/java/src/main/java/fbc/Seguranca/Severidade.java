package fbc.Seguranca;

/** Severidade de um resultado de ataque. */
public enum Severidade {
    CRITICA("critica"),
    ALTA("alta"),
    MEDIA("media"),
    BAIXA("baixa"),
    INFO("info"),
    PULADO("pulado"),
    DEMONSTRACAO("demonstracao"),
    ERRO("erro");

    private final String valor;

    Severidade(String valor) {
        this.valor = valor;
    }

    public String valor() {
        return valor;
    }

    @Override
    public String toString() {
        return valor;
    }
}

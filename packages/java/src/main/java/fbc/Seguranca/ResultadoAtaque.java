package fbc.Seguranca;

import java.util.Map;

/**
 * Resultado de rodar um ataque contra um alvo.
 *
 * {@code vulneravel = true} significa que o ataque ACHOU um problema (a cifra
 * falhou). {@code vulneravel = false} significa que a cifra resistiu a esse
 * ataque específico.
 */
public class ResultadoAtaque {
    private final String nomeAtaque;
    private final boolean vulneravel;
    private final Severidade severidade;
    private final String detalhes;
    private final Map<String, Object> dados;

    public ResultadoAtaque(String nomeAtaque, boolean vulneravel, Severidade severidade, String detalhes) {
        this(nomeAtaque, vulneravel, severidade, detalhes, null);
    }

    public ResultadoAtaque(
            String nomeAtaque,
            boolean vulneravel,
            Severidade severidade,
            String detalhes,
            Map<String, Object> dados) {
        this.nomeAtaque = nomeAtaque;
        this.vulneravel = vulneravel;
        this.severidade = severidade;
        this.detalhes = detalhes;
        this.dados = dados;
    }

    public String nomeAtaque() {
        return nomeAtaque;
    }

    public boolean vulneravel() {
        return vulneravel;
    }

    public Severidade severidade() {
        return severidade;
    }

    public String detalhes() {
        return detalhes;
    }

    public Map<String, Object> dados() {
        return dados;
    }

    public String linhaResumo() {
        String status;
        if (severidade == Severidade.PULADO) {
            status = "PULADO";
        } else if (severidade == Severidade.DEMONSTRACAO) {
            status = "DEMONSTRAÇÃO";
        } else {
            status = vulneravel ? "❌ VULNERÁVEL" : "✅ resistiu";
        }

        return "[" + status + "] " + nomeAtaque + " (" + severidade + "): " + detalhes;
    }
}

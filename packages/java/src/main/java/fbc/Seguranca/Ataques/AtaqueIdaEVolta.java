package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import java.util.ArrayList;
import java.util.List;

/**
 * Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido de
 * decrypt precisa devolver o texto original, em qualquer tamanho.
 */
public class AtaqueIdaEVolta implements AtaqueInterface {
    private final int tamanhoMaximo;

    public AtaqueIdaEVolta() {
        this(130);
    }

    public AtaqueIdaEVolta(int tamanhoMaximo) {
        this.tamanhoMaximo = tamanhoMaximo;
    }

    @Override
    public String nome() {
        return "Ida-e-volta (round trip)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        List<String> falhas = new ArrayList<>();
        for (int len = 0; len <= this.tamanhoMaximo; len++) {
            String texto = "Q".repeat(len);
            try {
                String token = alvo.encrypt(texto);
                String decifrado = alvo.decrypt(token);
                if (!decifrado.equals(texto)) {
                    falhas.add(String.valueOf(len));
                }
            } catch (Exception e) {
                String mensagem = e.getMessage() != null ? e.getMessage() : e.toString();
                falhas.add(len + " (erro: " + mensagem + ")");
            }
        }

        if (!falhas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    "Falhou em " + falhas.size() + " tamanho(s): "
                            + String.join(", ", falhas.subList(0, Math.min(10, falhas.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todos os " + (this.tamanhoMaximo + 1) + " tamanhos (0 a " + this.tamanhoMaximo + ") OK");
    }
}

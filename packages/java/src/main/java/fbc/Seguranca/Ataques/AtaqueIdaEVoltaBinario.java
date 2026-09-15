package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
 * verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
 * vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
 * truncation) só aparecem com bytes arbitrários.
 *
 * Adaptação Java: os dados são byte[]; como decrypt() devolve string (UTF-8),
 * comparamos com a representação UTF-8 dos mesmos bytes.
 */
public class AtaqueIdaEVoltaBinario implements AtaqueInterface {
    private final int tamanhoMaximo;

    public AtaqueIdaEVoltaBinario() {
        this(256);
    }

    public AtaqueIdaEVoltaBinario(int tamanhoMaximo) {
        this.tamanhoMaximo = tamanhoMaximo;
    }

    @Override
    public String nome() {
        return "Ida-e-volta com dados binários (inclui NUL)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        List<String> falhas = new ArrayList<>();

        for (int len = 0; len <= this.tamanhoMaximo; len++) {
            byte[] texto = len == 0 ? new byte[0] : Util.randomBytes(len);
            try {
                if (!alvo.decrypt(alvo.encrypt(texto)).equals(new String(texto, StandardCharsets.UTF_8))) {
                    falhas.add(String.valueOf(len));
                }
            } catch (Exception e) {
                String mensagem = e.getMessage() != null ? e.getMessage() : e.toString();
                falhas.add(len + " (erro: " + mensagem + ")");
            }
        }

        byte[] todos = new byte[256];
        for (int i = 0; i < 256; i++) {
            todos[i] = (byte) i;
        }
        if (!alvo.decrypt(alvo.encrypt(todos)).equals(new String(todos, StandardCharsets.UTF_8))) {
            falhas.add("todos os 256 valores de byte");
        }

        if (!falhas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    "Falhou em " + falhas.size() + " caso(s): "
                            + String.join(", ", falhas.subList(0, Math.min(10, falhas.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todos os tamanhos 0.." + this.tamanhoMaximo + " e os 256 valores de byte preservados");
    }
}

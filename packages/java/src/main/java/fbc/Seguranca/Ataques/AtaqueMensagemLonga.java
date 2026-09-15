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
 * Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
 * sincronização de bloco, repetição de keystream em blocos distantes ou
 * perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
 * curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
 * gera tokens diferentes.
 *
 * Adaptação Java: os dados são byte[]; como decrypt() devolve string (UTF-8),
 * comparamos com a representação UTF-8 dos mesmos bytes.
 */
public class AtaqueMensagemLonga implements AtaqueInterface {
    private final int[] tamanhos;

    public AtaqueMensagemLonga() {
        this(new int[] {1000, 10000, 100000});
    }

    public AtaqueMensagemLonga(int[] tamanhos) {
        this.tamanhos = tamanhos;
    }

    @Override
    public String nome() {
        return "Mensagens longas (multi-bloco)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        List<String> falhas = new ArrayList<>();

        for (int t : this.tamanhos) {
            byte[] texto = Util.randomBytes(t);
            try {
                String token = alvo.encrypt(texto);
                if (!alvo.decrypt(token).equals(new String(texto, StandardCharsets.UTF_8))) {
                    falhas.add(t + " bytes (conteúdo diferente)");
                }
            } catch (Exception e) {
                String mensagem = e.getMessage() != null ? e.getMessage() : e.toString();
                falhas.add(t + " bytes (erro: " + mensagem + ")");
            }
        }

        String texto = "A".repeat(1000);
        String t1 = alvo.encrypt(texto);
        String t2 = alvo.encrypt(texto);
        if (t1.equals(t2)) {
            falhas.add("tokens idênticos para o mesmo texto (IV não varia)");
        }

        if (!falhas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(), true, Severidade.CRITICA, "Falha em: " + String.join("; ", falhas));
        }

        List<String> lista = new ArrayList<>();
        for (int t : this.tamanhos) {
            lista.add(String.valueOf(t));
        }
        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Ida-e-volta OK em " + String.join(", ", lista) + " bytes; mesmo texto gera tokens distintos");
    }
}

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.util.ArrayList;
import java.util.List;

/**
 * A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
 * rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
 * bytes válida deve funcionar.
 */
public class AtaqueValidacaoChave implements AtaqueInterface {
    private final int[] tamanhos;

    public AtaqueValidacaoChave() {
        this(new int[] {0, 1, 16, 31, 33, 64});
    }

    public AtaqueValidacaoChave(int[] tamanhos) {
        this.tamanhos = tamanhos;
    }

    @Override
    public String nome() {
        return "Validação do tamanho da chave";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de CriptografiaAlvo para trocar a chave.");
        }

        String chaveOriginal = alvo.chaveDeTeste();
        List<Integer> aceitasIndevidamente = new ArrayList<>();
        boolean validaRejeitada = false;

        try {
            for (int len : this.tamanhos) {
                new CriptografiaAlvo("K".repeat(len));
                try {
                    alvo.encrypt("x");
                    aceitasIndevidamente.add(len);
                } catch (Exception e) {
                    // esperado
                }
            }

            new CriptografiaAlvo("K".repeat(32));
            try {
                alvo.encrypt("x");
            } catch (Exception e) {
                validaRejeitada = true;
            }
        } finally {
            new CriptografiaAlvo(chaveOriginal);
        }

        boolean vulneravel = !aceitasIndevidamente.isEmpty() || validaRejeitada;

        List<String> detalhes = new ArrayList<>();
        if (!aceitasIndevidamente.isEmpty()) {
            List<String> valores = new ArrayList<>();
            for (int len : aceitasIndevidamente) {
                valores.add(String.valueOf(len));
            }
            detalhes.add("chaves de tamanho inválido aceitas: " + String.join(", ", valores));
        }
        if (validaRejeitada) {
            detalhes.add("chave válida de 32 bytes foi rejeitada");
        }

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                vulneravel
                        ? String.join("; ", detalhes)
                        : "Tamanhos inválidos rejeitados e chave de 32 bytes aceita");
    }
}

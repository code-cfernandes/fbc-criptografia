package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CamposToken;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Se a comparação de integridade não for de tempo constante (ex: usar ===
 * em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
 * iniciais do campo de integridade batem, comparando o tempo de resposta -
 * e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
 *
 * Esse teste gera um token válido, cria versões adulteradas onde o campo
 * de integridade erra em posições DIFERENTES (início vs. fim do campo), e
 * compara o tempo médio de decrypt() entre os grupos. Uma diferença
 * estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
 * último byte" indica uma comparação vulnerável a timing.
 *
 * IMPORTANTE: testes de timing têm MUITO ruído (garbage collector, JIT,
 * agendamento do SO). Isso é uma checagem heurística grosseira, não uma
 * prova formal - trate qualquer resultado "vulnerável" como um convite pra
 * investigar o código-fonte diretamente, e um resultado "resistiu" como
 * "não detectei nesse experimento", não como garantia.
 */
public class AtaqueTiming implements AtaqueInterface {
    private final int repeticoesPorGrupo;

    public AtaqueTiming() {
        this(400);
    }

    public AtaqueTiming(int repeticoesPorGrupo) {
        this.repeticoesPorGrupo = repeticoesPorGrupo;
    }

    @Override
    public String nome() {
        return "Timing da verificação de integridade";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_encode/decode do alvo.");
        }

        String token = alvo.encrypt("MENSAGEM_PARA_TESTE_DE_TIMING");
        byte[] decodificado = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
        CamposToken campos = alvo.decompor(decodificado);
        int tamanhoIntegridade = campos.integridade.length;

        // Grupo A: erro logo no primeiro byte do campo de integridade.
        // Grupo B: erro no último byte.
        // Repete várias rodadas intercaladas pra diluir variação de carga
        // da máquina ao longo do tempo (evita viés de "a máquina esquentou").
        double[] medianasA = new double[8];
        double[] medianasB = new double[8];
        for (int rodada = 0; rodada < 8; rodada++) {
            medianasA[rodada] = this.medirGrupo(alvo, campos, 0);
            medianasB[rodada] = this.medirGrupo(alvo, campos, tamanhoIntegridade - 1);
        }

        double medianaA = 0.0;
        for (double v : medianasA) {
            medianaA += v;
        }
        medianaA /= medianasA.length;
        double medianaB = 0.0;
        for (double v : medianasB) {
            medianaB += v;
        }
        medianaB /= medianasB.length;
        double diferencaRelativa = Math.abs(medianaA - medianaB) / Math.max(medianaA, medianaB);

        // Limite arbitrário e conservador: só marca como suspeito se a
        // diferença for grande o bastante pra não ser só ruído de máquina
        // (na prática, comparações vulneráveis costumam mostrar diferenças
        // bem mais óbvias que isso quando o campo é curto).
        boolean vulneravel = diferencaRelativa > 0.15;

        Map<String, Object> dados = new HashMap<>();
        dados.put("mediana_inicio_ns", medianaA);
        dados.put("mediana_fim_ns", medianaB);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                String.format(
                                Locale.ROOT,
                                "mediana erro-no-início=%.0fns, mediana erro-no-fim=%.0fns, diferença relativa=%.1f%% (limite=15%%). ",
                                medianaA,
                                medianaB,
                                diferencaRelativa * 100)
                        + (vulneravel
                                ? "Diferença suspeita - investigar se a comparação usa hash_equals()."
                                : "Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal)."),
                dados);
    }

    private double medirGrupo(AlvoCriptografico alvo, CamposToken campos, int posicaoErro) {
        long[] tempos = new long[this.repeticoesPorGrupo];
        for (int r = 0; r < this.repeticoesPorGrupo; r++) {
            byte[] integ = campos.integridade.clone();
            integ[posicaoErro] = (byte) (integ[posicaoErro] ^ 0x01);
            CamposToken camposAdulterados = new CamposToken(integ, campos.ciphertext, campos.iv);

            String tokenAdulterado =
                    alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(camposAdulterados));

            long inicio = System.nanoTime();
            try {
                alvo.decrypt(tokenAdulterado);
            } catch (Exception e) {
                // esperado
            }
            tempos[r] = System.nanoTime() - inicio;
        }
        Arrays.sort(tempos);
        // usa a mediana em vez da média - muito mais robusta a outliers
        // de agendamento do SO, comum em testes de timing em ambiente
        // compartilhado.
        return tempos[tempos.length / 2];
    }
}

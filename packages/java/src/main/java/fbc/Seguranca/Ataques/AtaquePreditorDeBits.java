package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
 * primeira metade do keystream e mede a taxa de acerto na segunda metade.
 * Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
 * Qualquer coisa acima disso indica que os bits carregam dependência
 * explorável - o embrião de um ataque de predição de estado.
 */
public class AtaquePreditorDeBits implements AtaqueInterface {
    private final int tamanho;
    private final int contexto;
    private final double limiteTaxa;

    public AtaquePreditorDeBits() {
        this(16384, 8, 0.55);
    }

    public AtaquePreditorDeBits(int tamanho, int contexto, double limiteTaxa) {
        this.tamanho = tamanho;
        this.contexto = contexto;
        this.limiteTaxa = limiteTaxa;
    }

    @Override
    public String nome() {
        return "Previsibilidade de bits (preditor por contexto)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] ks = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8),
                Util.randomBytes(alvo.tamanhoIv()),
                "enc",
                this.tamanho);
        if (ks == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[] bits = this.paraBits(ks);
        int n = bits.length;
        int k = this.contexto;
        int total = 1 << k;
        int metade = n / 2;

        int[] uns = new int[total];
        int[] cont = new int[total];
        for (int i = k; i < metade; i++) {
            int ctx = this.contextoDe(bits, i, k);
            uns[ctx] += bits[i];
            cont[ctx]++;
        }

        int acertos = 0;
        int testes = 0;
        for (int i = metade; i < n; i++) {
            int ctx = this.contextoDe(bits, i, k);
            if (cont[ctx] == 0) {
                continue;
            }
            int predicao = uns[ctx] * 2 > cont[ctx] ? 1 : 0;
            if (predicao == bits[i]) {
                acertos++;
            }
            testes++;
        }

        double taxa = testes > 0 ? (double) acertos / testes : 0.5;
        boolean vulneravel = taxa > this.limiteTaxa;

        Map<String, Object> dados = new HashMap<>();
        dados.put("taxa", taxa);
        dados.put("testes", testes);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "taxa de acerto=%.2f%% com contexto de %d bits (esperado ~50%%, limite=%.0f%%) sobre %d testes",
                        taxa * 100,
                        k,
                        this.limiteTaxa * 100,
                        testes),
                dados);
    }

    private int contextoDe(int[] bits, int i, int k) {
        int ctx = 0;
        for (int j = i - k; j < i; j++) {
            ctx = (ctx << 1) | bits[j];
        }
        return ctx;
    }

    private int[] paraBits(byte[] bytes) {
        int[] bits = new int[bytes.length * 8];
        int idx = 0;
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            for (int j = 7; j >= 0; j--) {
                bits[idx++] = (b >> j) & 1;
            }
        }
        return bits;
    }
}

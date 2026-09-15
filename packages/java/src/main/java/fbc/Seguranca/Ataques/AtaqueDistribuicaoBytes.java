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
 * Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
 * 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
 * de byte saem com mais frequência que outros - sinal de fraqueza estatística
 * na função de mistura.
 */
public class AtaqueDistribuicaoBytes implements AtaqueInterface {
    private final int amostrasDeBlocos;
    private final int tamanhoBloco;

    public AtaqueDistribuicaoBytes() {
        this(500, 32);
    }

    public AtaqueDistribuicaoBytes(int amostrasDeBlocos, int tamanhoBloco) {
        this.amostrasDeBlocos = amostrasDeBlocos;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Distribuição de bytes (qui-quadrado)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[] contagem = new int[256];
        int total = 0;
        for (int i = 0; i < this.amostrasDeBlocos; i++) {
            byte[] ks = alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
            for (int j = 0; j < ks.length; j++) {
                contagem[ks[j] & 0xFF]++;
                total++;
            }
        }

        double esperado = (double) total / 256;
        double qui2 = 0.0;
        for (int c : contagem) {
            double d = c - esperado;
            qui2 += (d * d) / esperado;
        }

        // Com 255 graus de liberdade, valores acima de ~330 já são
        // estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
        boolean vulneravel = qui2 > 330;

        Map<String, Object> dados = new HashMap<>();
        dados.put("qui2", qui2);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "qui-quadrado=%.1f sobre %d bytes (255 graus de liberdade; >330 é suspeito)",
                        qui2,
                        total),
                dados);
    }
}

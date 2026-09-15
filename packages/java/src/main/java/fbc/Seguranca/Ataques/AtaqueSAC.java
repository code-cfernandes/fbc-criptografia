package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
 * esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
 * bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
 */
public class AtaqueSAC implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int amostras;
    private final double tolerancia;

    public AtaqueSAC() {
        this(32, 40, 0.05);
    }

    public AtaqueSAC(int tamanhoBloco, int amostras, double tolerancia) {
        this.tamanhoBloco = tamanhoBloco;
        this.amostras = amostras;
        this.tolerancia = tolerancia;
    }

    @Override
    public String nome() {
        return "SAC (Strict Avalanche Criterion)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int totalBits = this.tamanhoBloco * 8;
        int[] flips = new int[totalBits];
        int tamanhoIv = alvo.tamanhoIv();
        int total = 0;

        for (int pos = 0; pos < tamanhoIv; pos++) {
            for (int bit = 0; bit < 8; bit++) {
                for (int s = 0; s < this.amostras; s++) {
                    byte[] iv1 = Util.randomBytes(tamanhoIv);
                    byte[] iv2 = iv1.clone();
                    iv2[pos] = (byte) (iv2[pos] ^ (1 << bit));

                    byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv1, "enc", this.tamanhoBloco);
                    byte[] ks2 = alvo.gerarKeystreamBruto(chave, iv2, "enc", this.tamanhoBloco);

                    for (int j = 0; j < totalBits; j++) {
                        int b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
                        int b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
                        if (b1 != b2) {
                            flips[j]++;
                        }
                    }
                    total++;
                }
            }
        }

        int pior = -1;
        double piorDesvio = 0;
        double piorP = 0.5;
        for (int j = 0; j < totalBits; j++) {
            double p = (double) flips[j] / total;
            double desvio = Math.abs(p - 0.5);
            if (desvio > piorDesvio) {
                piorDesvio = desvio;
                pior = j;
                piorP = p;
            }
        }

        boolean vulneravel = piorDesvio > this.tolerancia;

        Map<String, Object> dados = new HashMap<>();
        dados.put("pior", pior);
        dados.put("pior_p", piorP);
        dados.put("desvio", piorDesvio);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "pior bit de saída=%d: p=%.2f%% (esperado 50%%, tolerância ±%.1f%%); %d amostras por bit de entrada",
                        pior,
                        piorP * 100,
                        this.tolerancia * 100,
                        total),
                dados);
    }
}

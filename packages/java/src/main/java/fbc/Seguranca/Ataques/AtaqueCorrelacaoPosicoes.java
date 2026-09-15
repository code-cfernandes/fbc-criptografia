package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
 * correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
 * posições de saída é exatamente o tipo de estrutura que o antigo bug da
 * "metade igual" produzia - e que a autocorrelação temporal pode não pegar.
 */
public class AtaqueCorrelacaoPosicoes implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;
    private final double limiteCorrelacao;

    public AtaqueCorrelacaoPosicoes() {
        this(3000, 32, 0.15);
    }

    public AtaqueCorrelacaoPosicoes(int amostras, int tamanhoBloco, double limiteCorrelacao) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
        this.limiteCorrelacao = limiteCorrelacao;
    }

    @Override
    public String nome() {
        return "Correlação entre posições do bloco";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        List<byte[]> blocos = new ArrayList<>();
        for (int i = 0; i < this.amostras; i++) {
            blocos.add(alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco));
        }

        List<String> suspeitos = new ArrayList<>();
        double pior = 0.0;

        for (int a = 0; a < this.tamanhoBloco; a++) {
            for (int b = a + 1; b < this.tamanhoBloco; b++) {
                double corr = this.pearson(blocos, a, b);
                if (Math.abs(corr) > Math.abs(pior)) {
                    pior = corr;
                }
                if (Math.abs(corr) > this.limiteCorrelacao) {
                    suspeitos.add(String.format(Locale.ROOT, "posições %d-%d (r=%.3f)", a, b, corr));
                }
            }
        }

        if (!suspeitos.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.ALTA,
                    suspeitos.size() + " par(es) correlacionado(s): "
                            + String.join("; ", suspeitos.subList(0, Math.min(10, suspeitos.size()))),
                    Map.of("suspeitos", suspeitos));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "Nenhum par de posições correlacionado acima de %.2f (pior |r|=%.3f)",
                        this.limiteCorrelacao,
                        Math.abs(pior)));
    }

    private double pearson(List<byte[]> blocos, int a, int b) {
        int n = blocos.size();
        double ma = 0.0;
        double mb = 0.0;
        for (byte[] d : blocos) {
            ma += (d[a] & 0xFF);
            mb += (d[b] & 0xFF);
        }
        ma /= n;
        mb /= n;

        double num = 0.0;
        double da = 0.0;
        double db = 0.0;
        for (byte[] d : blocos) {
            double xa = (d[a] & 0xFF) - ma;
            double xb = (d[b] & 0xFF) - mb;
            num += xa * xb;
            da += xa * xa;
            db += xb * xb;
        }

        return da > 0 && db > 0 ? num / Math.sqrt(da * db) : 0.0;
    }
}

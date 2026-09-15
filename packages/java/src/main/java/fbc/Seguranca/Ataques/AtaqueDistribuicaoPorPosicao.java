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

/**
 * O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
 * bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
 * soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
 */
public class AtaqueDistribuicaoPorPosicao implements AtaqueInterface {
    private final int amostrasDeBlocos;
    private final int tamanhoBloco;

    public AtaqueDistribuicaoPorPosicao() {
        this(2000, 32);
    }

    public AtaqueDistribuicaoPorPosicao(int amostrasDeBlocos, int tamanhoBloco) {
        this.amostrasDeBlocos = amostrasDeBlocos;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Distribuição de bytes por posição do bloco";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[][] contagens = new int[this.tamanhoBloco][256];
        for (int i = 0; i < this.amostrasDeBlocos; i++) {
            byte[] ks = alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
            for (int p = 0; p < this.tamanhoBloco; p++) {
                contagens[p][ks[p] & 0xFF]++;
            }
        }

        double esperado = (double) this.amostrasDeBlocos / 256;
        List<String> problemas = new ArrayList<>();
        double pior = 0.0;

        for (int p = 0; p < contagens.length; p++) {
            int[] c = contagens[p];
            double chi2 = 0.0;
            for (int v : c) {
                double d = v - esperado;
                chi2 += (d * d) / esperado;
            }
            pior = Math.max(pior, chi2);
            double z = (chi2 - 255) / Math.sqrt(510);
            if (z > 4.0) {
                problemas.add(String.format(Locale.ROOT, "posição %d chi2=%.1f", p, chi2));
            }
        }

        if (!problemas.isEmpty()) {
            return new ResultadoAtaque(nome(), true, Severidade.MEDIA, String.join("; ", problemas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "Todas as %d posições uniformes (pior chi2=%.1f, esperado ~255)",
                        this.tamanhoBloco,
                        pior));
    }
}

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
 * gerado (efeito avalanche). Números muito abaixo disso indicam difusão
 * fraca - foi o que achamos quando o número de rodadas de mistura era
 * baixo demais numa das versões anteriores.
 */
public class AtaqueAvalanche implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;
    private final double limiteMedia;
    private final double limitePiorCaso;

    public AtaqueAvalanche() {
        this(3000, 32, 0.45, 0.3);
    }

    public AtaqueAvalanche(int amostras, int tamanhoBloco, double limiteMedia, double limitePiorCaso) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
        this.limiteMedia = limiteMedia;
        this.limitePiorCaso = limitePiorCaso;
    }

    @Override
    public String nome() {
        return "Efeito avalanche";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int tamanhoIv = alvo.tamanhoIv();

        byte[] primeiro = alvo.gerarKeystreamBruto(chave, Util.randomBytes(tamanhoIv), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        double[] valores = new double[this.amostras];
        for (int t = 0; t < this.amostras; t++) {
            byte[] iv1 = Util.randomBytes(tamanhoIv);
            byte[] iv2 = iv1.clone();
            int pos = Util.randomInt(0, tamanhoIv - 1);
            iv2[pos] = (byte) (iv2[pos] ^ (1 << Util.randomInt(0, 7)));

            byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv1, "enc", this.tamanhoBloco);
            byte[] ks2 = alvo.gerarKeystreamBruto(chave, iv2, "enc", this.tamanhoBloco);

            valores[t] = (double) Util.bitsDiferentes(ks1, ks2) / (this.tamanhoBloco * 8);
        }

        Arrays.sort(valores);
        int n = valores.length;
        double soma = 0.0;
        for (double v : valores) {
            soma += v;
        }
        double media = soma / n;
        double piorCaso = valores[0];
        double percentil1 = valores[(int) (n * 0.01)];

        boolean vulneravel = media < this.limiteMedia || piorCaso < this.limitePiorCaso;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("pior_caso", piorCaso);

        String detalhes = String.format(
                java.util.Locale.ROOT,
                "média=%.1f%%, pior caso=%.1f%%, percentil 1%%=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)",
                media * 100,
                piorCaso * 100,
                percentil1 * 100,
                this.limiteMedia * 100,
                this.limitePiorCaso * 100);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                detalhes,
                dados);
    }
}

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
 * O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
 * CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
 * inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
 * Números baixos indicam que parte da chave tem pouca influência - o que
 * reduziria o espaço de busca de um atacante.
 */
public class AtaqueAvalancheChave implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;
    private final double limiteMedia;
    private final double limitePiorCaso;

    public AtaqueAvalancheChave() {
        this(3000, 32, 0.45, 0.3);
    }

    public AtaqueAvalancheChave(int amostras, int tamanhoBloco, double limiteMedia, double limitePiorCaso) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
        this.limiteMedia = limiteMedia;
        this.limitePiorCaso = limitePiorCaso;
    }

    @Override
    public String nome() {
        return "Efeito avalanche da chave";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chaveBase = alvo.chaveDeTeste().getBytes(StandardCharsets.ISO_8859_1);
        int lenChave = chaveBase.length;
        byte[] iv = Util.randomBytes(alvo.tamanhoIv());

        byte[] primeiro = alvo.gerarKeystreamBruto(chaveBase, iv, "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        double[] valores = new double[this.amostras];
        for (int t = 0; t < this.amostras; t++) {
            byte[] chave = chaveBase.clone();
            int pos = Util.randomInt(0, lenChave - 1);
            chave[pos] = (byte) (chave[pos] ^ (1 << Util.randomInt(0, 7)));

            byte[] ks1 = alvo.gerarKeystreamBruto(chaveBase, iv, "enc", this.tamanhoBloco);
            byte[] ks2 = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanhoBloco);

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

        boolean vulneravel = media < this.limiteMedia || piorCaso < this.limitePiorCaso;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("pior_caso", piorCaso);

        String detalhes = String.format(
                java.util.Locale.ROOT,
                "média=%.1f%%, pior caso=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)",
                media * 100,
                piorCaso * 100,
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

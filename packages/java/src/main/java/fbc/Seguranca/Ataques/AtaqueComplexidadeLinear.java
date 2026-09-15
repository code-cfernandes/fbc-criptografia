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
 * Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
 * reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
 * complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
 * um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
 * seria atacável resolvendo um sistema linear em vez de força bruta.
 */
public class AtaqueComplexidadeLinear implements AtaqueInterface {
    private final int bitsPorAmostra;
    private final int amostras;
    private final double limiteRelativo;

    public AtaqueComplexidadeLinear() {
        this(1024, 5, 0.4);
    }

    public AtaqueComplexidadeLinear(int bitsPorAmostra, int amostras, double limiteRelativo) {
        this.bitsPorAmostra = bitsPorAmostra;
        this.amostras = amostras;
        this.limiteRelativo = limiteRelativo;
    }

    @Override
    public String nome() {
        return "Complexidade linear (Berlekamp-Massey)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(chave, Util.randomBytes(alvo.tamanhoIv()), "enc", 64);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        double[] relativos = new double[this.amostras];
        double pior = 1.0;
        for (int a = 0; a < this.amostras; a++) {
            byte[] bytes = alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.bitsPorAmostra / 8);
            int[] bits = this.paraBits(bytes, this.bitsPorAmostra);
            double relativo = (double) this.berlekampMassey(bits) / this.bitsPorAmostra;
            relativos[a] = relativo;
            pior = Math.min(pior, relativo);
        }

        double soma = 0.0;
        for (double r : relativos) {
            soma += r;
        }
        double media = soma / relativos.length;
        boolean vulneravel = pior < this.limiteRelativo;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("pior", pior);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "complexidade linear relativa: média=%.1f%%, pior=%.1f%% de %d bits (esperado ~50%%; limite>=%.0f%%)",
                        media * 100,
                        pior * 100,
                        this.bitsPorAmostra,
                        this.limiteRelativo * 100),
                dados);
    }

    private int[] paraBits(byte[] bytes, int limite) {
        int[] bits = new int[limite];
        int idx = 0;
        for (int i = 0; i < bytes.length && idx < limite; i++) {
            int b = bytes[i] & 0xFF;
            for (int j = 7; j >= 0 && idx < limite; j--) {
                bits[idx++] = (b >> j) & 1;
            }
        }
        return bits;
    }

    /** Algoritmo de Berlekamp-Massey sobre GF(2). */
    private int berlekampMassey(int[] s) {
        int n = s.length;
        int[] c = new int[n];
        c[0] = 1;
        int[] b = new int[n];
        b[0] = 1;
        int l = 0;
        int m = -1;

        for (int i = 0; i < n; i++) {
            int d = s[i];
            for (int j = 1; j <= l; j++) {
                d ^= c[j] & s[i - j];
            }

            if (d == 1) {
                int[] t = c.clone();
                int shift = i - m;
                for (int j = 0; j + shift < n; j++) {
                    c[j + shift] ^= b[j];
                }
                if (l <= i / 2) {
                    l = i + 1 - l;
                    m = i;
                    System.arraycopy(t, 0, b, 0, n);
                }
            }
        }

        return l;
    }
}

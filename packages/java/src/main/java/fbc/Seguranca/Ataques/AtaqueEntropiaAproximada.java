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
 * Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
 * previsibilidade local: para uma sequência aleatória, a chance de repetir um
 * bloco de m bits deve cair suavemente conforme m cresce. Estruturas
 * periódicas/recorrentes produzem ApEn anômala.
 *
 * O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
 * um valor esperado teórico. Comparamos o keystream com um CONTROLE de
 * random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
 * estatisticamente indistinguíveis.
 */
public class AtaqueEntropiaAproximada implements AtaqueInterface {
    private final int tamanho;
    private final int m;
    private final int controles;
    private final int amostrasKeystream;
    private final double limiteZ;

    public AtaqueEntropiaAproximada() {
        this(4096, 8, 12, 3, 5.0);
    }

    public AtaqueEntropiaAproximada(
            int tamanho, int m, int controles, int amostrasKeystream, double limiteZ) {
        this.tamanho = tamanho;
        this.m = m;
        this.controles = controles;
        this.amostrasKeystream = amostrasKeystream;
        this.limiteZ = limiteZ;
    }

    @Override
    public String nome() {
        return "Entropia aproximada (ApEn vs controle aleatório)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", 64);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        double[] chiControle = new double[this.controles];
        for (int c = 0; c < this.controles; c++) {
            chiControle[c] = this.estatistico(Util.randomBytes(this.tamanho));
        }
        double mediaControle = 0.0;
        for (double v : chiControle) {
            mediaControle += v;
        }
        mediaControle /= chiControle.length;
        double variancia = 0.0;
        for (double v : chiControle) {
            double d = v - mediaControle;
            variancia += d * d;
        }
        double desvioControle = Math.sqrt(variancia / Math.max(1, chiControle.length - 1));

        double[] chiKeystream = new double[this.amostrasKeystream];
        for (int k = 0; k < this.amostrasKeystream; k++) {
            byte[] ks = alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanho);
            chiKeystream[k] = this.estatistico(ks);
        }
        double mediaKeystream = 0.0;
        for (double v : chiKeystream) {
            mediaKeystream += v;
        }
        mediaKeystream /= chiKeystream.length;

        double z = desvioControle > 0 ? (mediaKeystream - mediaControle) / desvioControle : 0.0;
        boolean vulneravel = Math.abs(z) > this.limiteZ;

        Map<String, Object> dados = new HashMap<>();
        dados.put("chi_keystream", mediaKeystream);
        dados.put("chi_controle", mediaControle);
        dados.put("z", z);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "chi2 keystream=%.1f, controle=%.1f (sd=%.1f), z=%.2f (limite=%.1f)",
                        mediaKeystream,
                        mediaControle,
                        desvioControle,
                        z,
                        this.limiteZ),
                dados);
    }

    /** chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1). */
    private double estatistico(byte[] bytes) {
        int[] bits = this.paraBits(bytes);
        int n = bits.length;
        double apen = this.phi(bits, this.m, n) - this.phi(bits, this.m + 1, n);
        return 2 * n * (Math.log(2) - apen);
    }

    private double phi(int[] bits, int m, int n) {
        int total = 1 << m;
        int[] contagem = new int[total];
        int janelas = n - m + 1;

        for (int i = 0; i < janelas; i++) {
            int v = 0;
            for (int j = 0; j < m; j++) {
                v = (v << 1) | bits[i + j];
            }
            contagem[v]++;
        }

        double soma = 0.0;
        for (int c : contagem) {
            if (c > 0) {
                double p = (double) c / janelas;
                soma += p * Math.log(p);
            }
        }

        return soma;
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

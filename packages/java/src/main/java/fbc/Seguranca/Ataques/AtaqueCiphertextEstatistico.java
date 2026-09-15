package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
 * (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
 * de cifra sólida deve parecer ruído mesmo com plaintext variado.
 */
public class AtaqueCiphertextEstatistico implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoTexto;
    private final double zLimite;

    public AtaqueCiphertextEstatistico() {
        this(200, 64, 4);
    }

    public AtaqueCiphertextEstatistico(int amostras, int tamanhoTexto, double zLimite) {
        this.amostras = amostras;
        this.tamanhoTexto = tamanhoTexto;
        this.zLimite = zLimite;
    }

    @Override
    public String nome() {
        return "Estatística do ciphertext (chi²/runs/autocorrelação)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int[] contagem = new int[256];
        int[] bytes = new int[this.amostras * this.tamanhoTexto];
        int totalBytes = 0;

        for (int s = 0; s < this.amostras; s++) {
            byte[] texto = Util.randomBytes(this.tamanhoTexto);
            String token = alvo.encrypt(texto);
            byte[] campos = alvo.decompor(alvo.base64urlDecode(token.substring(alvo.prefixo().length()))).ciphertext;
            for (byte b : campos) {
                contagem[b & 0xFF]++;
                bytes[totalBytes++] = b & 0xFF;
            }
        }

        double esperado = (double) totalBytes / 256;
        double chi2 = 0;
        for (int b = 0; b < 256; b++) {
            double d = contagem[b] - esperado;
            chi2 += (d * d) / esperado;
        }

        // runs test nos bits do ciphertext
        int uns = 0;
        int[] bits = new int[totalBytes * 8];
        int idx = 0;
        for (int i = 0; i < totalBytes; i++) {
            int b = bytes[i];
            for (int k = 7; k >= 0; k--) {
                int bit = (b >> k) & 1;
                bits[idx++] = bit;
                uns += bit;
            }
        }
        int n = bits.length;
        double pi = (double) uns / n;
        int runs = 1;
        for (int i = 1; i < n; i++) {
            if (bits[i] != bits[i - 1]) {
                runs++;
            }
        }
        double esperadoRuns = 2.0 * n * pi * (1 - pi);
        double desvioRuns = 2 * Math.sqrt(2.0 * n) * pi * (1 - pi);
        double zRuns = desvioRuns > 0 ? Math.abs(runs - esperadoRuns) / desvioRuns : 0;

        // autocorrelação lag-1
        double media = 0.0;
        for (int i = 0; i < totalBytes; i++) {
            media += bytes[i];
        }
        media /= totalBytes;
        double num = 0;
        double den = 0;
        for (int i = 0; i < totalBytes; i++) {
            den += (bytes[i] - media) * (bytes[i] - media);
        }
        for (int i = 0; i < totalBytes - 1; i++) {
            num += (bytes[i] - media) * (bytes[i + 1] - media);
        }
        double autocorr = den > 0 ? num / den : 0;

        List<String> problemas = new ArrayList<>();
        if (chi2 > 330) {
            problemas.add(String.format(Locale.ROOT, "qui-quadrado=%.1f (>330 suspeito)", chi2));
        }
        if (zRuns > this.zLimite) {
            problemas.add(String.format(Locale.ROOT, "runs z=%.2f", zRuns));
        }
        if (Math.abs(autocorr) > 0.1) {
            problemas.add(String.format(Locale.ROOT, "autocorrelação=%.3f", autocorr));
        }

        boolean vulneravel = !problemas.isEmpty();

        Map<String, Object> dados = new HashMap<>();
        dados.put("chi2", chi2);
        dados.put("runs_z", zRuns);
        dados.put("autocorrelacao", autocorr);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                vulneravel
                        ? String.join("; ", problemas)
                        : String.format(
                                Locale.ROOT,
                                "qui-quadrado=%.1f sobre %d bytes, runs z=%.2f, autocorrelação=%.3f - todos dentro do esperado",
                                chi2,
                                totalBytes,
                                zRuns,
                                autocorr),
                dados);
    }
}

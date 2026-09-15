package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
 * global (monobit), frequência por posição de bit, teste de runs e frequência
 * por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
 * e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
 *
 * Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
 * pra não depender de funções numéricas especiais.
 */
public class AtaqueBateriaEstatistica implements AtaqueInterface {
    private final int tamanho;
    private final double zLimite;

    public AtaqueBateriaEstatistica() {
        this(16384, 4.0);
    }

    public AtaqueBateriaEstatistica(int tamanho, double zLimite) {
        this.tamanho = tamanho;
        this.zLimite = zLimite;
    }

    @Override
    public String nome() {
        return "Bateria estatística de bits (monobit/runs/blocos)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] ks = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanho);
        if (ks == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[] bits = this.paraBits(ks);
        int n = bits.length;
        List<String> problemas = new ArrayList<>();
        Map<String, Object> dados = new HashMap<>();

        // 1) Monobit: soma +1/-1
        int soma = 0;
        for (int b : bits) {
            soma += b == 1 ? 1 : -1;
        }
        double zMonobit = Math.abs(soma) / Math.sqrt(n);
        dados.put("monobit_z", zMonobit);
        if (zMonobit > this.zLimite) {
            problemas.add(String.format(Locale.ROOT, "monobit z=%.2f", zMonobit));
        }

        // 2) Frequência por posição de bit
        int[] unsPorPos = new int[8];
        int[] contaPorPos = new int[8];
        for (int i = 0; i < ks.length; i++) {
            int b = ks[i] & 0xFF;
            for (int bit = 0; bit < 8; bit++) {
                if (((b >> bit) & 1) == 1) {
                    unsPorPos[bit]++;
                }
                contaPorPos[bit]++;
            }
        }
        Map<Integer, Double> posViesadas = new LinkedHashMap<>();
        for (int bit = 0; bit < 8; bit++) {
            double frac = (double) unsPorPos[bit] / contaPorPos[bit];
            double z = Math.abs(frac - 0.5) / (0.5 / Math.sqrt(contaPorPos[bit]));
            if (z > this.zLimite) {
                posViesadas.put(bit, frac);
            }
        }
        dados.put("bit_posicao_viesadas", posViesadas);
        if (!posViesadas.isEmpty()) {
            List<String> chaves = new ArrayList<>();
            for (Integer k : posViesadas.keySet()) {
                chaves.add(String.valueOf(k));
            }
            problemas.add("viés por posição de bit: " + String.join(", ", chaves));
        }

        // 3) Runs test
        double pi = 0.0;
        for (int b : bits) {
            pi += b;
        }
        pi /= n;
        double runsZ = 0.0;
        if (Math.abs(pi - 0.5) < 2 / Math.sqrt(n)) {
            int runs = 1;
            for (int i = 1; i < n; i++) {
                if (bits[i] != bits[i - 1]) {
                    runs++;
                }
            }
            double esperado = 2 * n * pi * (1 - pi);
            double desvio = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
            runsZ = Math.abs(runs - esperado) / desvio;
            dados.put("runs_z", runsZ);
            if (runsZ > this.zLimite) {
                problemas.add(String.format(Locale.ROOT, "runs z=%.2f", runsZ));
            }
        }

        // 4) Frequência por bloco (M = 128 bits)
        int m = 128;
        int numBlocos = n / m;
        double blocosChi2 = 0.0;
        if (numBlocos > 0) {
            double chi = 0.0;
            for (int i = 0; i < numBlocos; i++) {
                int uns = 0;
                for (int j = 0; j < m; j++) {
                    uns += bits[i * m + j];
                }
                double d = ((double) uns / m) - 0.5;
                chi += d * d;
            }
            chi *= 4 * m;
            double zBlocos = (chi - numBlocos) / Math.sqrt(2 * numBlocos);
            blocosChi2 = chi;
            dados.put("blocos_chi2", chi);
            dados.put("blocos_z", zBlocos);
            if (zBlocos > this.zLimite) {
                problemas.add(String.format(Locale.ROOT, "frequência por bloco chi2=%.1f", chi));
            }
        }

        if (!problemas.isEmpty()) {
            return new ResultadoAtaque(nome(), true, Severidade.MEDIA, String.join("; ", problemas), dados);
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "monobit z=%.2f, runs z=%.2f, blocos chi2=%.1f - todos abaixo do limite z=%.0f",
                        zMonobit,
                        runsZ,
                        blocosChi2,
                        this.zLimite),
                dados);
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

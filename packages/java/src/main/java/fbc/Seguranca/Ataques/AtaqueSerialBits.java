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
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
 * gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
 * locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
 * aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
 */
public class AtaqueSerialBits implements AtaqueInterface {
    private final int tamanho;
    private final int[] ordens;

    public AtaqueSerialBits() {
        this(4096, new int[] {2, 3, 4});
    }

    public AtaqueSerialBits(int tamanho, int[] ordens) {
        this.tamanho = tamanho;
        this.ordens = ordens;
    }

    @Override
    public String nome() {
        return "Teste serial (padrões de bits sobrepostos)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] ks = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8),
                Util.randomBytes(alvo.tamanhoIv()),
                "enc",
                this.tamanho);
        if (ks == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[] bits = this.paraBits(ks);
        int n = bits.length;

        List<String> problemas = new ArrayList<>();
        Map<String, Object> dados = new HashMap<>();

        for (int m : this.ordens) {
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

            double esperado = (double) janelas / total;
            double chi2 = 0.0;
            for (int c : contagem) {
                chi2 += (c - esperado) * (c - esperado) / esperado;
            }
            double dof = total - 1;
            // Wilson-Hilferty: aproxima chi² por normal de forma bem mais precisa
            // para dof pequeno. O z "ingênuo" (chi2-dof)/sqrt(2*dof) dá ~5% de falso
            // positivo em dof=3 (m=2); este fica em ~0.005%.
            double z = (Math.pow(chi2 / dof, 1.0 / 3) - (1 - 2.0 / (9 * dof)))
                    / Math.sqrt(2.0 / (9 * dof));

            Map<String, Object> info = new HashMap<>();
            info.put("chi2", chi2);
            info.put("z", z);
            dados.put("m" + m, info);

            if (z > 6.0) {
                problemas.add(String.format(Locale.ROOT, "m=%d chi2=%.1f (z=%.1f)", m, chi2, z));
            }
        }

        if (!problemas.isEmpty()) {
            return new ResultadoAtaque(nome(), true, Severidade.MEDIA, String.join("; ", problemas), dados);
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Padrões sobrepostos de 2/3/4 bits com frequência uniforme",
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

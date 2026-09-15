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
 * Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
 * passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
 * pequeno que o monobit quase não vê faz o desvio acumulado crescer.
 * Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
 */
public class AtaqueCusum implements AtaqueInterface {
    private final int tamanho;
    private final double limiteZ;

    public AtaqueCusum() {
        this(8192, 4.0);
    }

    public AtaqueCusum(int tamanho, double limiteZ) {
        this.tamanho = tamanho;
        this.limiteZ = limiteZ;
    }

    @Override
    public String nome() {
        return "Somas cumulativas (cusum)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] ks = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanho);
        if (ks == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int soma = 0;
        int maxAbs = 0;
        for (int i = 0; i < ks.length; i++) {
            int b = ks[i] & 0xFF;
            for (int bit = 7; bit >= 0; bit--) {
                soma += ((b >> bit) & 1) == 1 ? 1 : -1;
                maxAbs = Math.max(maxAbs, Math.abs(soma));
            }
        }
        int n = ks.length * 8;
        double z = maxAbs / Math.sqrt(n);
        boolean vulneravel = z > this.limiteZ;

        Map<String, Object> dados = new HashMap<>();
        dados.put("max_abs", maxAbs);
        dados.put("z", z);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "max|S|=%d sobre %d bits, max|S|/sqrt(n)=%.2f (limite=%.1f)",
                        maxAbs,
                        n,
                        z,
                        this.limiteZ),
                dados);
    }
}

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
 * Procura linearidade no checksum, que seria fatal para um MAC:
 *  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
 *  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
 *     cada a; se repetir muito, existe um diferencial de alta probabilidade
 *     que ajuda a forjar MACs.
 */
public class AtaqueLinearidadeChecksum implements AtaqueInterface {
    private final int amostrasLinearidade;
    private final int amostrasDiferencial;
    private final int tamanhoEntrada;

    public AtaqueLinearidadeChecksum() {
        this(5000, 500, 32);
    }

    public AtaqueLinearidadeChecksum(int amostrasLinearidade, int amostrasDiferencial, int tamanhoEntrada) {
        this.amostrasLinearidade = amostrasLinearidade;
        this.amostrasDiferencial = amostrasDiferencial;
        this.tamanhoEntrada = tamanhoEntrada;
    }

    @Override
    public String nome() {
        return "Linearidade e diferenciais do checksum";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chaveMac = "M".repeat(32).getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.checksumBruto("teste".getBytes(StandardCharsets.UTF_8), chaveMac);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe checksumBruto.");
        }

        int relacoesLineares = 0;
        for (int i = 0; i < this.amostrasLinearidade; i++) {
            byte[] a = Util.randomBytes(this.tamanhoEntrada);
            byte[] b = Util.randomBytes(this.tamanhoEntrada);
            byte[] lhs = this.xorBytes(
                    alvo.checksumBruto(a, chaveMac), alvo.checksumBruto(b, chaveMac));
            byte[] rhs = alvo.checksumBruto(this.xorBytes(a, b), chaveMac);
            if (Arrays.equals(lhs, rhs)) {
                relacoesLineares++;
            }
        }

        int maxRepeticoesDiferencial = 0;
        for (int d = 0; d < 5; d++) {
            byte[] delta = Util.randomBytes(this.tamanhoEntrada);
            Map<String, Integer> vistos = new HashMap<>();
            for (int i = 0; i < this.amostrasDiferencial; i++) {
                byte[] a = Util.randomBytes(this.tamanhoEntrada);
                byte[] dif = this.xorBytes(
                        alvo.checksumBruto(this.xorBytes(a, delta), chaveMac),
                        alvo.checksumBruto(a, chaveMac));
                String chaveDif = Util.bytesParaHex(dif);
                vistos.put(chaveDif, vistos.getOrDefault(chaveDif, 0) + 1);
            }
            int maxVistos = 0;
            for (int c : vistos.values()) {
                if (c > maxVistos) {
                    maxVistos = c;
                }
            }
            maxRepeticoesDiferencial = Math.max(maxRepeticoesDiferencial, maxVistos);
        }

        boolean vulneravel = relacoesLineares > 0 || maxRepeticoesDiferencial > 1;

        Map<String, Object> dados = new HashMap<>();
        dados.put("relacoes_lineares", relacoesLineares);
        dados.put("max_repeticoes_diferencial", maxRepeticoesDiferencial);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                relacoesLineares + "/" + this.amostrasLinearidade
                        + " relações lineares; maior repetição de diferencial="
                        + maxRepeticoesDiferencial + " (esperado 1)",
                dados);
    }

    private byte[] xorBytes(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        }
        return out;
    }
}

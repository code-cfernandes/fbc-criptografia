package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
 * produzir keystream anômalo (repetição, período curto, viés de bits ou
 * distribuição de bytes distorcida). Complementa o ataque de chaves
 * degeneradas, que só checa a saída do encrypt.
 */
public class AtaqueChavesFracas implements AtaqueInterface {
    private final int tamanho;
    private final double toleranciaBits;

    public AtaqueChavesFracas() {
        this(2048, 0.05);
    }

    public AtaqueChavesFracas(int tamanho, double toleranciaBits) {
        this.tamanho = tamanho;
        this.toleranciaBits = toleranciaBits;
    }

    @Override
    public String nome() {
        return "Chaves fracas (busca dirigida)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int len = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;

        Map<String, byte[]> casos = new LinkedHashMap<>();
        casos.put("zeros", new byte[len]);
        byte[] ff = new byte[len];
        java.util.Arrays.fill(ff, (byte) 0xFF);
        casos.put("0xFF", ff);
        byte[] alternada = new byte[len];
        for (int i = 0; i < len; i++) {
            alternada[i] = (byte) (i % 2 == 0 ? 0xAA : 0x55);
        }
        casos.put("alternada AA/55", alternada);
        byte[] incremental = new byte[len];
        for (int i = 0; i < len; i++) {
            incremental[i] = (byte) (i & 0xFF);
        }
        casos.put("incremental", incremental);
        byte[] umBit = new byte[len];
        for (int i = 0; i < len; i++) {
            umBit[i] = (byte) (i == 0 ? 1 : 0);
        }
        casos.put("um bit", umBit);
        byte[] repetido = new byte[len];
        java.util.Arrays.fill(repetido, (byte) 0x01);
        casos.put("byte repetido 0x01", repetido);
        byte[] padraoAB = new byte[len];
        for (int i = 0; i < len; i++) {
            padraoAB[i] = (byte) (i % 2 == 0 ? 0x41 : 0x42);
        }
        casos.put("padrão AB", padraoAB);

        byte[] ivFixo = new byte[alvo.tamanhoIv()];
        List<String> anomalias = new ArrayList<>();

        for (Map.Entry<String, byte[]> caso : casos.entrySet()) {
            byte[] ks = alvo.gerarKeystreamBruto(caso.getValue(), ivFixo, "enc", this.tamanho);

            Set<String> blocos = new HashSet<>();
            int repetidos = 0;
            for (int i = 0; i + 32 <= ks.length; i += 32) {
                String hex = Util.bytesParaHex(java.util.Arrays.copyOfRange(ks, i, i + 32));
                if (blocos.contains(hex)) {
                    repetidos++;
                } else {
                    blocos.add(hex);
                }
            }

            double fracaoUns = (double) Util.contarBitsBuffer(ks) / (ks.length * 8);
            double desvioBits = Math.abs(fracaoUns - 0.5);

            if (repetidos > 0) {
                anomalias.add(caso.getKey() + ": " + repetidos + " bloco(s) repetido(s)");
            }
            if (desvioBits > this.toleranciaBits) {
                anomalias.add(caso.getKey() + ": viés de bits " + String.format(Locale.ROOT, "%.1f%%", fracaoUns * 100));
            }
        }

        boolean vulneravel = !anomalias.isEmpty();

        Map<String, Object> dados = new HashMap<>();
        dados.put("anomalias", anomalias);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                vulneravel
                        ? "Anomalias: " + String.join("; ", anomalias.subList(0, Math.min(5, anomalias.size())))
                        : "Nenhuma das " + casos.size() + " chaves fracas produziu keystream anômalo ("
                                + this.tamanho + " bytes cada)",
                dados);
    }
}

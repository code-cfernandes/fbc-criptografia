package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
 * (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
 * mesmo quando a maioria das entradas se comporta bem. Testa especificamente
 * esses casos extremos, que testes com entrada aleatória raramente cobrem.
 */
public class AtaqueIVsDegenerados implements AtaqueInterface {
    @Override
    public String nome() {
        return "IVs degenerados (zero, 0xFF, alternado)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int tamanhoIv = alvo.tamanhoIv();
        int tamanhoBloco = 32;

        byte[] primeiro = alvo.gerarKeystreamBruto(chave, new byte[tamanhoIv], "enc", tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        Map<String, byte[]> casos = new LinkedHashMap<>();
        casos.put("zero", new byte[tamanhoIv]);
        byte[] ff = new byte[tamanhoIv];
        Arrays.fill(ff, (byte) 0xFF);
        casos.put("0xFF", ff);
        byte[] aa = new byte[tamanhoIv];
        Arrays.fill(aa, (byte) 0xAA);
        casos.put("alternado 0xAA", aa);
        byte[] c55 = new byte[tamanhoIv];
        Arrays.fill(c55, (byte) 0x55);
        casos.put("alternado 0x55", c55);
        byte[] crescente = new byte[tamanhoIv];
        for (int i = 0; i < tamanhoIv; i++) {
            crescente[i] = (byte) i;
        }
        casos.put("crescente", crescente);

        Map<String, Map<String, Object>> problemas = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : casos.entrySet()) {
            byte[] ks = alvo.gerarKeystreamBruto(chave, e.getValue(), "enc", tamanhoBloco);

            int metade = tamanhoBloco / 2;
            boolean periodico = Arrays.equals(
                    Arrays.copyOfRange(ks, 0, metade),
                    Arrays.copyOfRange(ks, metade, metade + metade));

            Set<Integer> unicos = new HashSet<>();
            for (byte b : ks) {
                unicos.add(b & 0xFF);
            }
            int bytesUnicos = unicos.size();
            boolean poucaVariedade = bytesUnicos < tamanhoBloco * 0.5;

            if (periodico || poucaVariedade) {
                Map<String, Object> info = new HashMap<>();
                info.put("periodico", periodico);
                info.put("bytesUnicos", bytesUnicos);
                problemas.put(e.getKey(), info);
            }
        }

        if (!problemas.isEmpty()) {
            List<String> detalhes = new ArrayList<>();
            for (Map.Entry<String, Map<String, Object>> e : problemas.entrySet()) {
                Map<String, Object> info = e.getValue();
                detalhes.add(e.getKey() + " (periódico="
                        + (((Boolean) info.get("periodico")) ? "sim" : "não")
                        + ", bytes únicos=" + info.get("bytesUnicos") + "/" + tamanhoBloco + ")");
            }
            return new ResultadoAtaque(
                    nome(), true, Severidade.ALTA, String.join("; ", detalhes), new HashMap<>(problemas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Nenhum dos " + casos.size() + " IVs degenerados testados produziu saída anômala");
    }
}

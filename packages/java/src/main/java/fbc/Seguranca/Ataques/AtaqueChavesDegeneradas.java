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
 * Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
 * (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
 * produzir keystream degenerado - e aqui testamos no pior cenário, com IV
 * zerado junto, pra isolar a contribuição da chave.
 */
public class AtaqueChavesDegeneradas implements AtaqueInterface {
    private final int tamanhoBloco;

    public AtaqueChavesDegeneradas() {
        this(32);
    }

    public AtaqueChavesDegeneradas(int tamanhoBloco) {
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int tamChave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;
        byte[] ivZero = new byte[alvo.tamanhoIv()];

        byte[] primeiro = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8), ivZero, "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        byte[] seqCrescente = new byte[512];
        for (int i = 0; i < 512; i++) {
            seqCrescente[i] = (byte) (i % 256);
        }

        Map<String, byte[]> casos = new LinkedHashMap<>();
        casos.put("zero", new byte[tamChave]);
        byte[] ff = new byte[tamChave];
        Arrays.fill(ff, (byte) 0xFF);
        casos.put("0xFF", ff);
        byte[] aa = new byte[tamChave];
        Arrays.fill(aa, (byte) 0xAA);
        casos.put("alternada 0xAA", aa);
        byte[] c55 = new byte[tamChave];
        Arrays.fill(c55, (byte) 0x55);
        casos.put("alternada 0x55", c55);
        byte[] repA = new byte[tamChave];
        Arrays.fill(repA, (byte) 0x41);
        casos.put("repetida \"A\"", repA);
        casos.put("crescente", Arrays.copyOf(seqCrescente, tamChave));

        Map<String, Map<String, Object>> problemas = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : casos.entrySet()) {
            byte[] chave = e.getValue();
            byte[] ks = alvo.gerarKeystreamBruto(chave, ivZero, "enc", this.tamanhoBloco);

            int metade = this.tamanhoBloco / 2;
            boolean periodico = Arrays.equals(
                    Arrays.copyOfRange(ks, 0, metade), Arrays.copyOfRange(ks, metade, metade + metade));
            Set<Integer> unicos = new HashSet<>();
            for (byte b : ks) {
                unicos.add(b & 0xFF);
            }
            int bytesUnicos = unicos.size();

            if (periodico || bytesUnicos < this.tamanhoBloco * 0.5) {
                Map<String, Object> info = new HashMap<>();
                info.put("periodico", periodico);
                info.put("bytes_unicos", bytesUnicos);
                problemas.put(e.getKey(), info);
            }
        }

        if (!problemas.isEmpty()) {
            List<String> detalhes = new ArrayList<>();
            for (Map.Entry<String, Map<String, Object>> e : problemas.entrySet()) {
                Map<String, Object> info = e.getValue();
                detalhes.add(e.getKey() + " (periódico=" + (((Boolean) info.get("periodico")) ? "sim" : "não")
                        + ", bytes únicos=" + info.get("bytes_unicos") + "/" + this.tamanhoBloco + ")");
            }
            return new ResultadoAtaque(
                    nome(), true, Severidade.ALTA, String.join("; ", detalhes), new HashMap<>(problemas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Nenhuma das " + casos.size() + " chaves degeneradas testadas produziu saída anômala");
    }
}

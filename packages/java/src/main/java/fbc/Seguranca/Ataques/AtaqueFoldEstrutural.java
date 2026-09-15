package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Esse é o ataque que pegou o bug mais sério que encontramos: quando a
 * distância de mistura era exatamente metade do bloco, TODOS os IVs
 * aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
 * Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
 */
public class AtaqueFoldEstrutural implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;

    public AtaqueFoldEstrutural() {
        this(5000, 32);
    }

    public AtaqueFoldEstrutural(int amostras, int tamanhoBloco) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Fold estrutural (metades/quartos/oitavos repetidos)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int[] candidatos = {2, 4, 8, 16};
        List<Integer> divisores = new ArrayList<>();
        for (int d : candidatos) {
            if (this.tamanhoBloco % d == 0 && this.tamanhoBloco / d >= 1) {
                divisores.add(d);
            }
        }
        Map<Integer, Integer> ocorrencias = new LinkedHashMap<>();
        for (int d : divisores) {
            ocorrencias.put(d, 0);
        }

        // Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
        // a chance de colisão por acaso é ~1/256^tam por par comparado -
        // desprezível para tam >= 2, então qualquer contagem > 0 já é
        // suspeita o bastante pra investigar (ajustamos a margem pra
        // fatias de 1-2 bytes, onde colisão por acaso é mais provável).
        for (int i = 0; i < this.amostras; i++) {
            byte[] ks = alvo.gerarKeystreamBruto(
                    chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanhoBloco);
            for (int divisor : divisores) {
                int tamFatia = this.tamanhoBloco / divisor;
                byte[] primeiraFatia = Arrays.copyOfRange(ks, 0, tamFatia);
                for (int j = 1; j < divisor; j++) {
                    byte[] fatia = Arrays.copyOfRange(ks, j * tamFatia, j * tamFatia + tamFatia);
                    if (Arrays.equals(fatia, primeiraFatia)) {
                        ocorrencias.put(divisor, ocorrencias.get(divisor) + 1);
                        break;
                    }
                }
            }
        }

        Map<Integer, Integer> problemas = new LinkedHashMap<>();
        for (int divisor : divisores) {
            int c = ocorrencias.get(divisor);
            if (c > margem(divisor)) {
                problemas.put(divisor, c);
            }
        }

        if (!problemas.isEmpty()) {
            List<String> detalhes = new ArrayList<>();
            for (Map.Entry<Integer, Integer> e : problemas.entrySet()) {
                detalhes.add("1/" + e.getKey() + " do bloco repetido em " + e.getValue() + "/" + this.amostras);
            }
            Map<String, Object> dados = new LinkedHashMap<>();
            for (Map.Entry<Integer, Integer> e : ocorrencias.entrySet()) {
                dados.put(String.valueOf(e.getKey()), e.getValue());
            }
            return new ResultadoAtaque(nome(), true, Severidade.CRITICA, String.join(", ", detalhes), dados);
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Nenhuma repetição estrutural acima do ruído esperado: " + jsonOcorrencias(ocorrencias));
    }

    private int margem(int divisor) {
        return this.tamanhoBloco / divisor <= 2 ? (int) (this.amostras * 0.01) + 3 : 5;
    }

    private static String jsonOcorrencias(Map<Integer, Integer> ocorrencias) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<Integer, Integer> e : ocorrencias.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append('"').append(e.getKey()).append("\":").append(e.getValue());
        }
        return sb.append("}").toString();
    }
}

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
 * Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
 * autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
 * estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
 * keystream aleatório deve ter todos esses indicadores perto de zero/50%.
 */
public class AtaqueAutocorrelacao implements AtaqueInterface {
    private final int tamanho;
    private final int tamanhoBloco;

    public AtaqueAutocorrelacao() {
        this(8192, 32);
    }

    public AtaqueAutocorrelacao(int tamanho, int tamanhoBloco) {
        this.tamanho = tamanho;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Autocorrelação e periodicidade do keystream";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] ks = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(alvo.tamanhoIv()), "enc", this.tamanho);
        if (ks == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        double serial = this.correlacao(ks, 1);

        int[] lags = {2, 4, 8, 16, 32, 64, 128, 256};
        Map<Integer, Double> suspeitos = new LinkedHashMap<>();
        for (int lag : lags) {
            double c = this.correlacao(ks, lag);
            if (Math.abs(c) > 0.1) {
                suspeitos.put(lag, c);
            }
        }

        List<byte[]> blocos = new ArrayList<>();
        for (int i = 0; i < ks.length; i += this.tamanhoBloco) {
            int fim = Math.min(i + this.tamanhoBloco, ks.length);
            byte[] bloco = new byte[fim - i];
            System.arraycopy(ks, i, bloco, 0, fim - i);
            blocos.add(bloco);
        }
        Set<String> blocosUnicos = new HashSet<>();
        for (byte[] b : blocos) {
            blocosUnicos.add(Util.bytesParaHex(b));
        }
        int blocosRepetidos = blocos.size() - blocosUnicos.size();

        int uns = Util.contarBitsBuffer(ks);
        double fracaoUns = (double) uns / (ks.length * 8);

        List<String> problemas = new ArrayList<>();
        if (Math.abs(serial) > 0.1) {
            problemas.add(String.format(Locale.ROOT, "correlação serial=%.3f", serial));
        }
        if (!suspeitos.isEmpty()) {
            List<String> chaves = new ArrayList<>();
            for (Integer k : suspeitos.keySet()) {
                chaves.add(String.valueOf(k));
            }
            problemas.add("autocorrelação em lag(s) " + String.join(", ", chaves));
        }
        if (blocosRepetidos > 0) {
            problemas.add(blocosRepetidos + " bloco(s) de " + this.tamanhoBloco + " bytes repetido(s)");
        }
        if (fracaoUns < 0.45 || fracaoUns > 0.55) {
            problemas.add(String.format(Locale.ROOT, "balanço de bits=%.1f%% de 1s", fracaoUns * 100));
        }

        if (!problemas.isEmpty()) {
            return new ResultadoAtaque(nome(), true, Severidade.MEDIA, String.join("; ", problemas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "serial=%.3f, nenhum lag com correlação >10%%, 0 blocos repetidos em %d, %.1f%% de bits 1",
                        serial,
                        blocos.size(),
                        fracaoUns * 100));
    }

    private double correlacao(byte[] s, int lag) {
        int n = s.length;
        if (n <= lag) {
            return 0.0;
        }

        double soma = 0;
        for (int i = 0; i < n; i++) {
            soma += (s[i] & 0xFF);
        }
        double media = soma / n;

        double num = 0.0;
        double den = 0.0;
        for (int i = 0; i < n; i++) {
            double d = (s[i] & 0xFF) - media;
            den += d * d;
        }
        for (int i = 0; i < n - lag; i++) {
            num += ((s[i] & 0xFF) - media) * ((s[i + lag] & 0xFF) - media);
        }

        return den > 0 ? num / den : 0.0;
    }
}

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
 * 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
 * schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
 * estrutura (distância de Hamming baixa).
 */
public class AtaqueChaveRelacionada implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int ivPorDelta;
    private final double limiteMedia;
    private final double limitePior;

    public AtaqueChaveRelacionada() {
        this(32, 3, 0.45, 0.3);
    }

    public AtaqueChaveRelacionada(
            int tamanhoBloco, int ivPorDelta, double limiteMedia, double limitePior) {
        this.tamanhoBloco = tamanhoBloco;
        this.ivPorDelta = ivPorDelta;
        this.limiteMedia = limiteMedia;
        this.limitePior = limitePior;
    }

    @Override
    public String nome() {
        return "Chave relacionada (related-key)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chaveBase = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int len = chaveBase.length;

        byte[][] deltas = new byte[2 * len + 1][];
        for (int i = 0; i < len; i++) {
            byte[] d = new byte[len];
            d[i] = 0x01;
            deltas[i] = d;
        }
        for (int i = 0; i < len; i++) {
            byte[] d = new byte[len];
            d[i] = (byte) 0xFF;
            deltas[len + i] = d;
        }
        byte[] complemento = new byte[len];
        for (int i = 0; i < len; i++) {
            complemento[i] = (byte) ((chaveBase[i] ^ 0xFF) & 0xFF);
        }
        deltas[2 * len] = complemento;

        double[] valores = new double[deltas.length * this.ivPorDelta];
        int totalBits = this.tamanhoBloco * 8;
        int idx = 0;

        for (byte[] delta : deltas) {
            byte[] chaveRelacionada = chaveBase.clone();
            for (int i = 0; i < len; i++) {
                chaveRelacionada[i] = (byte) ((chaveRelacionada[i] ^ delta[i]) & 0xFF);
            }
            for (int s = 0; s < this.ivPorDelta; s++) {
                byte[] iv = Util.randomBytes(alvo.tamanhoIv());
                byte[] ks1 = alvo.gerarKeystreamBruto(chaveBase, iv, "enc", this.tamanhoBloco);
                byte[] ks2 = alvo.gerarKeystreamBruto(chaveRelacionada, iv, "enc", this.tamanhoBloco);
                valores[idx++] = (double) Util.bitsDiferentes(ks1, ks2) / totalBits;
            }
        }

        double soma = 0.0;
        double pior = 1.0;
        for (double v : valores) {
            soma += v;
            pior = Math.min(pior, v);
        }
        double media = soma / valores.length;
        boolean vulneravel = media < this.limiteMedia || pior < this.limitePior;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("pior", pior);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "média=%.1f%%, pior=%.1f%% em %d pares (limites: média>=%.0f%%, pior>=%.0f%%)",
                        media * 100,
                        pior * 100,
                        valores.length,
                        this.limiteMedia * 100,
                        this.limitePior * 100),
                dados);
    }
}

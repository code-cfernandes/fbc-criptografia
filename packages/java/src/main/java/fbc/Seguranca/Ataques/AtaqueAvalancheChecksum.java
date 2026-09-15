package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
 * interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
 * dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
 * posição específica significa que aquele byte quase não influencia o MAC -
 * uma pista forte de que a mistura tem um "ponto cego" estrutural.
 *
 * Varre TODAS as posições/bits da entrada (não amostra aleatória) para
 * apontar exatamente onde está o ponto fraco.
 */
public class AtaqueAvalancheChecksum implements AtaqueInterface {
    private final int mensagensPorCombinacao;
    private final int tamanhoEntrada;
    private final double limiteMedia;
    private final double limitePiorCaso;

    public AtaqueAvalancheChecksum() {
        this(10, 32, 0.4, 0.4);
    }

    public AtaqueAvalancheChecksum(
            int mensagensPorCombinacao, int tamanhoEntrada, double limiteMedia, double limitePiorCaso) {
        this.mensagensPorCombinacao = mensagensPorCombinacao;
        this.tamanhoEntrada = tamanhoEntrada;
        this.limiteMedia = limiteMedia;
        this.limitePiorCaso = limitePiorCaso;
    }

    @Override
    public String nome() {
        return "Efeito avalanche do checksum/MAC";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chaveMac = "M".repeat(32).getBytes(StandardCharsets.UTF_8);

        byte[] primeiro = alvo.checksumBruto("teste".getBytes(StandardCharsets.UTF_8), chaveMac);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe checksumBruto.");
        }
        int tamanhoSaida = primeiro.length;

        double somaGlobal = 0.0;
        int combinacoes = 0;
        int piorPosicao = -1;
        int piorBit = -1;
        double piorValor = 1.0;

        for (int pos = 0; pos < this.tamanhoEntrada; pos++) {
            for (int bit = 0; bit < 8; bit++) {
                double soma = 0.0;
                for (int m = 0; m < this.mensagensPorCombinacao; m++) {
                    byte[] entrada = Util.randomBytes(this.tamanhoEntrada);
                    byte[] alterada = entrada.clone();
                    alterada[pos] = (byte) (alterada[pos] ^ (1 << bit));

                    byte[] h1 = alvo.checksumBruto(entrada, chaveMac);
                    byte[] h2 = alvo.checksumBruto(alterada, chaveMac);

                    soma += (double) Util.bitsDiferentes(h1, h2) / (tamanhoSaida * 8);
                }
                double media = soma / this.mensagensPorCombinacao;

                somaGlobal += media;
                combinacoes++;
                if (media < piorValor) {
                    piorValor = media;
                    piorPosicao = pos;
                    piorBit = bit;
                }
            }
        }

        double mediaGlobal = somaGlobal / combinacoes;
        boolean vulneravel = mediaGlobal < this.limiteMedia || piorValor < this.limitePiorCaso;

        Severidade severidade;
        if (!vulneravel) {
            severidade = Severidade.INFO;
        } else if (piorValor < 0.3) {
            severidade = Severidade.ALTA;
        } else {
            severidade = Severidade.MEDIA;
        }

        Map<String, Object> dados = new HashMap<>();
        dados.put("media_global", mediaGlobal);
        Map<String, Object> pior = new HashMap<>();
        pior.put("posicao", piorPosicao);
        pior.put("bit", piorBit);
        pior.put("valor", piorValor);
        dados.put("pior", pior);

        String detalhes = String.format(
                java.util.Locale.ROOT,
                "média global=%.1f%%; pior caso=%.1f%% na entrada[posição=%d, bit=%d] sobre %d bytes de MAC (limites: média>=%.0f%%, pior>=%.0f%%)",
                mediaGlobal * 100,
                piorValor * 100,
                piorPosicao,
                piorBit,
                tamanhoSaida,
                this.limiteMedia * 100,
                this.limitePiorCaso * 100);

        return new ResultadoAtaque(nome(), vulneravel, severidade, detalhes, dados);
    }
}

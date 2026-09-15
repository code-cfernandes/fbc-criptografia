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
 * Procura colisões no checksum() via paradoxo do aniversário: gera muitas
 * mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
 * propósito aqui - testar resistência a colisão é uma propriedade do
 * ALGORITMO, independente de a chave ser secreta ou não; é assim que se
 * testa qualquer função de hash/MAC na prática).
 *
 * Testa dois níveis:
 * 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
 *    aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
 *    tentativas pelo paradoxo do aniversário).
 * 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
 *    estatisticamente com poucas dezenas de milhares de tentativas (o
 *    paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
 *    pra 50% de chance). Isso não quebra o MAC completo (que depende dos
 *    32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
 *    útil pra saber se a composição das rodadas está de fato preservando
 *    a força total, ou se há alguma correlação entre elas.
 */
public class AtaqueColisaoChecksum implements AtaqueInterface {
    private final int amostras;

    public AtaqueColisaoChecksum() {
        this(200000);
    }

    public AtaqueColisaoChecksum(int amostras) {
        this.amostras = amostras;
    }

    @Override
    public String nome() {
        return "Colisão no checksum (paradoxo do aniversário)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chaveDeMac = "M".repeat(32).getBytes(StandardCharsets.UTF_8); // chave conhecida de propósito - ver docblock

        byte[] primeiro = alvo.checksumBruto("teste".getBytes(StandardCharsets.UTF_8), chaveDeMac);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe checksumBruto.");
        }

        Map<String, byte[]> vistosCompleto = new HashMap<>();
        Map<String, byte[]> vistosTruncado = new HashMap<>();
        byte[][] colisaoCompleta = null;
        byte[][] colisaoTruncada = null;

        for (int i = 0; i < this.amostras; i++) {
            byte[] mensagem = Util.randomBytes(20);
            byte[] hash = alvo.checksumBruto(mensagem, chaveDeMac);

            if (colisaoCompleta == null) {
                String chaveHash = Util.bytesParaHex(hash);
                byte[] anterior = vistosCompleto.get(chaveHash);
                if (anterior != null) {
                    colisaoCompleta = new byte[][] {anterior, mensagem};
                } else {
                    vistosCompleto.put(chaveHash, mensagem);
                }
            }

            if (colisaoTruncada == null) {
                String truncado = Util.bytesParaHex(Arrays.copyOfRange(hash, 0, 4));
                byte[] anterior = vistosTruncado.get(truncado);
                if (anterior != null) {
                    colisaoTruncada = new byte[][] {anterior, mensagem};
                } else {
                    vistosTruncado.put(truncado, mensagem);
                }
            }

            if (colisaoCompleta != null && colisaoTruncada != null) {
                break;
            }
        }

        // Colisão no checksum COMPLETO com essa amostra pequena seria uma
        // falha estrutural séria (a probabilidade por acaso é desprezível).
        if (colisaoCompleta != null) {
            Map<String, Object> dados = new HashMap<>();
            dados.put("msg1_hex", Util.bytesParaHex(colisaoCompleta[0]));
            dados.put("msg2_hex", Util.bytesParaHex(colisaoCompleta[1]));
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    "COLISÃO COMPLETA encontrada em " + vistosCompleto.size()
                            + " amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.",
                    dados);
        }

        // Colisão truncada (32 bits) é esperada estatisticamente - não é
        // "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
        // força que deveriam ter (nem mais, nem menos).
        String infoTruncada = colisaoTruncada != null
                ? "colisão de 32 bits encontrada em " + vistosTruncado.size()
                        + " amostras (esperado pelo paradoxo do aniversário)"
                : "nenhuma colisão de 32 bits em " + vistosTruncado.size()
                        + " amostras (um pouco abaixo do esperado, mas não conclusivo)";

        Map<String, Object> dados = new HashMap<>();
        dados.put("amostras_completo", vistosCompleto.size());
        dados.put("amostras_truncado", vistosTruncado.size());

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Nenhuma colisão completa em " + this.amostras
                        + " amostras (esperado). Nível truncado (32 bits): " + infoTruncada + ".",
                dados);
    }
}

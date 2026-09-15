package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
 * chave do MAC ('mac'). Se os dois streams não forem independentes, um
 * atacante que recupere o keystream de dados (ataque de texto conhecido)
 * pode derivar a chave do MAC e FORJAR tokens válidos.
 *
 * O teste procura dois sintomas de acoplamento:
 *  1. a distância de Hamming média entre os streams deve ser ~50%;
 *  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
 *     uma máscara fixa, o mac é 100% previsível a partir do enc.
 */
public class AtaqueIndependenciaProposito implements AtaqueInterface {
    private final int amostras;
    private final int tamanho;

    public AtaqueIndependenciaProposito() {
        this(2000, 32);
    }

    public AtaqueIndependenciaProposito(int amostras, int tamanho) {
        this.amostras = amostras;
        this.tamanho = tamanho;
    }

    @Override
    public String nome() {
        return "Independência entre keystreams de propósitos diferentes (enc x mac)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] primeiro = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8),
                Util.randomBytes(alvo.tamanhoIv()),
                "enc",
                this.tamanho);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int lenChave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;
        double soma = 0.0;
        Set<String> mascaras = new HashSet<>();
        for (int i = 0; i < this.amostras; i++) {
            byte[] chave = Util.randomBytes(lenChave);
            byte[] iv = Util.randomBytes(alvo.tamanhoIv());

            byte[] enc = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanho);
            byte[] mac = alvo.gerarKeystreamBruto(chave, iv, "mac", this.tamanho);

            soma += (double) Util.bitsDiferentes(enc, mac) / (this.tamanho * 8);
            mascaras.add(Util.bytesParaHex(this.xorBytes(enc, mac)));
        }

        double media = soma / this.amostras;
        int mascarasDistintas = mascaras.size();
        boolean vulneravel = media < 0.4 || media > 0.6 || mascarasDistintas < this.amostras;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("mascaras_distintas", mascarasDistintas);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "Hamming médio enc x mac=%.1f%% (esperado ~50%%); %d máscara(s) XOR distinta(s) em %d amostras%s",
                        media * 100,
                        mascarasDistintas,
                        this.amostras,
                        mascarasDistintas < this.amostras
                                ? " - MÁSCARA REPETIDA: mac previsível a partir de enc!"
                                : ""),
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

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
 * Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
 * venham do mesmo texto, se comportam como se fossem de textos diferentes
 * (distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).
 *
 * Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
 * parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
 * cifrar 500 textos diferentes.
 */
public class AtaqueCorrelacaoMesmoPlaintext implements AtaqueInterface {
    private final int amostras;
    private final String textoFixo;

    public AtaqueCorrelacaoMesmoPlaintext() {
        this(300, "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR");
    }

    public AtaqueCorrelacaoMesmoPlaintext(int amostras, String textoFixo) {
        this.amostras = amostras;
        this.textoFixo = textoFixo;
    }

    @Override
    public String nome() {
        return "Correlação entre ciphertexts do mesmo plaintext";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_decode do alvo.");
        }

        List<byte[]> ciphertexts = new ArrayList<>();
        for (int i = 0; i < this.amostras; i++) {
            String token = alvo.encrypt(this.textoFixo);
            byte[] decodificado = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
            ciphertexts.add(alvo.decompor(decodificado).ciphertext);
        }

        // Compara pares aleatórios de ciphertexts (não todos contra todos,
        // pra manter o custo baixo) e mede a distância de Hamming média.
        int comparacoes = Math.min(500, (this.amostras * (this.amostras - 1)) / 2);
        List<Double> distancias = new ArrayList<>();
        for (int c = 0; c < comparacoes; c++) {
            int i = Util.randomInt(0, this.amostras - 1);
            int j = Util.randomInt(0, this.amostras - 1);
            if (i == j) {
                continue;
            }
            distancias.add(this.distanciaHammingRelativa(ciphertexts.get(i), ciphertexts.get(j)));
        }

        double soma = 0.0;
        for (double v : distancias) {
            soma += v;
        }
        double media = soma / distancias.size();

        // Também confere que nenhum PAR de ciphertexts é idêntico (o que
        // indicaria reuso de IV+key, capturado de outro ângulo).
        Set<String> unicos = new HashSet<>();
        for (byte[] b : ciphertexts) {
            unicos.add(Util.bytesParaHex(b));
        }
        int duplicatas = ciphertexts.size() - unicos.size();

        boolean vulneravel = media < 0.4 || media > 0.6 || duplicatas > 0;

        Map<String, Object> dados = new HashMap<>();
        dados.put("media", media);
        dados.put("duplicatas", duplicatas);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "distância de Hamming média entre ciphertexts do mesmo texto: %.1f%% (esperado ~50%%), %d duplicata(s) exata(s) em %d amostras",
                        media * 100,
                        duplicatas,
                        this.amostras),
                dados);
    }

    private double distanciaHammingRelativa(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        if (len == 0) {
            return 0.5;
        }
        int diff = 0;
        for (int i = 0; i < len; i++) {
            diff += Util.contarBits1((a[i] ^ b[i]) & 0xFF);
        }
        return (double) diff / (len * 8);
    }
}

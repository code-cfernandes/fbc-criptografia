package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Vetores de referência (Known Answer Tests) e interoperabilidade.
 *
 * A mesma cifra é implementada em PHP, Node, TypeScript, Python e Bash. Este
 * ataque fixa keystreams e tokens conhecidos: se QUALQUER implementação divergir,
 * ela não reproduz estes valores e o ataque acusa.
 *
 * Os tokens foram gerados com a chave de teste padrão
 * ('pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf').
 */
public class AtaqueInteroperabilidade implements AtaqueInterface {
    private static final String CHAVE_FIXA = "K".repeat(32);

    private static final class VetorKeystream {
        final String iv;
        final String proposito;
        final int tamanho;
        final String esperado;

        VetorKeystream(String iv, String proposito, int tamanho, String esperado) {
            this.iv = iv;
            this.proposito = proposito;
            this.tamanho = tamanho;
            this.esperado = esperado;
        }
    }

    private static final VetorKeystream[] VETORES = {
        new VetorKeystream(
                "00000000000000000000000000000000", "enc", 32,
                "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249"),
        new VetorKeystream(
                "00000000000000000000000000000000", "enc", 64,
                "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249"
                        + "a9b8fa2ec5a08abdae48729fe50aa1def4d6af963ecb11a46d1a4604046741a7"),
        new VetorKeystream(
                "00000000000000000000000000000000", "mac", 32,
                "ebaec6df127deb7dac57d584f86a13c53cfc74974da9f6594fd831acf3d07bb1"),
        new VetorKeystream(
                "000102030405060708090a0b0c0d0e0f", "enc", 32,
                "0c8c9ba9ee81e6b9d00bd84b22c4180afd2a0c595f35a6be05b9d0a3ba37baf9"),
        new VetorKeystream(
                "000102030405060708090a0b0c0d0e0f", "mac", 64,
                "2173c8774d071e983d895aeaa0cc2dd22d5da18b8427a98ee9ad89297eb03e0e"
                        + "961303b58b65bf2b6f48b7cfb2a04b1a7a9406f8a45605a1774d6fb8ddeda30d"),
        new VetorKeystream(
                "ffffffffffffffffffffffffffffffff", "enc", 32,
                "c2e2551794dea9cd8904550745adcc28baaf0179773eb0db171dc77701edae28"),
        new VetorKeystream(
                "30313233343536373839616263646566", "enc", 64,
                "ca36c5f105ea153f4dc6a591e97f7098bbc7c3aef2491423d9fb2ce612c84b72"
                        + "32009cb847d44cd2f72b47d0a293dd6227b96ce6cd2ba825e951b98e12819c0c"),
        new VetorKeystream(
                "30313233343536373839616263646566", "mac", 32,
                "22aec48f7ec4731e402cc64a1b31955d7757c75c5ce606e28eb47c8ad936af3f"),
    };

    private static final class VetorToken {
        final String texto;
        final String token;

        VetorToken(String texto, String token) {
            this.texto = texto;
            this.token = token;
        }
    }

    private static final VetorToken[] TOKENS = {
        new VetorToken(
                "",
                "FBCbBmERldK0rQ3SAu1PxJ7drr2ie-jwhDLefEaGiBsJ_2autyPG4oSs6DXEM_w6-6x"),
        new VetorToken(
                "A",
                "FBCo5OnvHbHG6nILqXCjGzVYo32jIC9I_PAqQ9CvRxggyiYKwhedK4ynN65_SSrE_mezQ"),
        new VetorToken(
                "TESTE",
                "FBCn7T3VBZFYnvG41Dx4VYn-tyKKd3QheLJ1kw7oDb9EhSUEfnTtlEN2Rxp1xaskppvmGSmeTI"),
        new VetorToken(
                "mensagem de interoperabilidade entre linguagens",
                "FBCqgHvQ_SGLjte-SDNMHt3LyNB8qGUfMxn_N1PqWGdQmyE4iHtA3k45aAygQnBpqAXYxlwIxkDumz3ln33vAttxUwIuYExCrG-LaYLBUVEyuX49X86mScMpOd3isnqYhU"),
    };

    @Override
    public String nome() {
        return "Interoperabilidade e vetores conhecidos (KAT)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        List<String> falhas = new ArrayList<>();

        for (VetorKeystream v : VETORES) {
            byte[] ks = alvo.gerarKeystreamBruto(
                    CHAVE_FIXA.getBytes(StandardCharsets.UTF_8),
                    Util.hexParaBytes(v.iv),
                    v.proposito,
                    v.tamanho);
            if (!Util.bytesParaHex(ks).equals(v.esperado)) {
                falhas.add("keystream iv=" + v.iv + " prop=" + v.proposito + " tam=" + v.tamanho);
            }
        }

        for (VetorToken t : TOKENS) {
            try {
                if (!alvo.decrypt(t.token).equals(t.texto)) {
                    falhas.add("token não decifrou para " + jsonString(t.texto));
                }
            } catch (Exception e) {
                falhas.add("token rejeitado: " + jsonString(t.texto));
            }
        }

        if (!falhas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.ALTA,
                    falhas.size() + " divergência(s) de interoperabilidade: "
                            + String.join("; ", falhas.subList(0, Math.min(5, falhas.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                VETORES.length + " vetores de keystream e " + TOKENS.length
                        + " tokens de referência conferem");
    }

    private static String jsonString(String s) {
        return "\"" + s + "\"";
    }
}

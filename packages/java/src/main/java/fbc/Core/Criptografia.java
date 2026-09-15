package fbc.Core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cifra caseira educacional - porte de Criptografia.php / Criptografia.ts.
 *
 * Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
 *
 * Ver Criptografia.php para os comentários completos sobre o design (difusão
 * tipo butterfly, distâncias Fibonacci->primo, rotação via Pi). Este arquivo
 * replica a lógica byte a byte, sem "melhorias" - qualquer mudança de
 * comportamento aqui quebraria compatibilidade com tokens gerados pelas outras
 * versões.
 *
 * A chave é lida de System.getenv("FBC_KEY"). Como Java não permite alterar o
 * ambiente do processo, a suíte de ataques usa definirChave() para sobrescrever
 * a chave durante os testes; quando nenhuma sobrescrita está ativa, a variável
 * de ambiente é usada.
 */
public final class Criptografia {
    public static final int TAM_BLOCO = 32;

    // Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
    private static final int[] DISTANCIAS_DIFUSAO = {3, 5, 11, 19, 41, 3, 5, 11, 19, 41};

    private static final String DIGITOS_PI =
            "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static String chaveSobrescrita = null;

    private Criptografia() {
    }

    /** Usada pela suíte de ataques para trocar a chave durante os testes. */
    public static void definirChave(String chave) {
        chaveSobrescrita = chave;
    }

    public static String getChaveAtual() {
        return chaveSobrescrita != null ? chaveSobrescrita : System.getenv("FBC_KEY");
    }

    static byte[] getKey() {
        String chave = getChaveAtual();
        if (chave == null) {
            throw new IllegalArgumentException("Chave deve ter 32 bytes.");
        }
        byte[] key = chave.getBytes(StandardCharsets.UTF_8);
        if (key.length != 32) {
            throw new IllegalArgumentException("Chave deve ter 32 bytes.");
        }
        return key;
    }

    public static int rotEsquerda8(int byteVal, int n) {
        n &= 7;
        byteVal &= 0xFF;
        if (n == 0) {
            return byteVal;
        }
        return ((byteVal << n) | (byteVal >>> (8 - n))) & 0xFF;
    }

    public static int rotEsquerda32(int val, int n) {
        n &= 31;
        if (n == 0) {
            return val;
        }
        return (val << n) | (val >>> (32 - n));
    }

    private static int rotacaoDoRound(int roundIdx) {
        int d = DIGITOS_PI.charAt(roundIdx % DIGITOS_PI.length()) - '0';
        return (d % 7) + 1;
    }

    /** Gera {@code tamanho} bytes de keystream a partir de KEY + IV + propósito. */
    public static byte[] gerarKeystream(byte[] key, byte[] iv, String proposito, int tamanho) {
        final int bloco = TAM_BLOCO;
        final int ivLen = iv.length;
        final int keyLen = key.length;
        final byte[] propositoBuf = proposito.getBytes(StandardCharsets.UTF_8);

        int[] a = new int[bloco];
        int[] b = new int[bloco];
        for (int pos = 0; pos < bloco; pos++) {
            a[pos] = (key[pos % keyLen] & 0xFF) ^ (iv[pos % ivLen] & 0xFF);
            b[pos] = (key[(pos + 1) % keyLen] & 0xFF) ^ (iv[(pos + 1) % ivLen] & 0xFF);
        }

        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        int roundIdx = 0;
        int posFibBase = 0;

        while (saida.size() < tamanho) {
            for (int dist : DISTANCIAS_DIFUSAO) {
                int[] novoB = new int[bloco];
                for (int pos = 0; pos < bloco; pos++) {
                    int aAtual = a[pos];
                    int bAtual = b[pos];
                    int n = rotacaoDoRound(roundIdx);

                    int soma = (aAtual + bAtual) & 0xFF;
                    soma = rotEsquerda8(soma, n);
                    soma ^= propositoBuf[(posFibBase + pos) % propositoBuf.length] & 0xFF;
                    // A chave participa de CADA rodada, não só do estado inicial.
                    soma ^= key[(posFibBase + pos + roundIdx) % keyLen] & 0xFF;
                    soma = (soma * 131) & 0xFF;

                    a[pos] = bAtual;
                    novoB[pos] = soma;
                }

                // Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR.
                int[] misturado = new int[bloco];
                for (int pos = 0; pos < bloco; pos++) {
                    int vizinho = novoB[(pos + dist) % bloco];
                    misturado[pos] = rotEsquerda8(novoB[pos], 1) ^ vizinho;
                }
                b = misturado;
                roundIdx++;
            }

            posFibBase += bloco;
            for (int pos = 0; pos < bloco; pos++) {
                saida.write(b[pos]);
            }
        }

        byte[] completo = saida.toByteArray();
        return completo.length == tamanho ? completo : Arrays.copyOf(completo, tamanho);
    }

    public static byte[] xorBytes(byte[] dados, byte[] keystream) {
        byte[] out = new byte[dados.length];
        for (int i = 0; i < dados.length; i++) {
            out[i] = (byte) ((dados[i] ^ keystream[i]) & 0xFF);
        }
        return out;
    }

    /** "MAC" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes. */
    public static byte[] checksum(byte[] dados, byte[] key) {
        byte[] saida = new byte[32];
        int keyLen = key.length;
        int len = dados.length;

        for (int rodada = 0; rodada < 8; rodada++) {
            int acumulador = 0x811c9dc5 ^ (rodada * 0x01000193);

            for (int i = 0; i < len; i++) {
                int b = (dados[i] & 0xFF) ^ (key[(i + rodada) % keyLen] & 0xFF);
                acumulador = acumulador ^ b;
                acumulador = acumulador * 16777619;
                acumulador = rotEsquerda32(acumulador, (i % 13) + 1);
            }

            // Finalização: sem isso, o último byte processado sofre avalanche fraca.
            for (int k = 0; k < 3; k++) {
                acumulador = acumulador ^ (acumulador >>> 16);
                acumulador = acumulador * 16777619;
                acumulador = rotEsquerda32(acumulador, 13);
            }

            saida[rodada * 4] = (byte) ((acumulador >>> 24) & 0xFF);
            saida[rodada * 4 + 1] = (byte) ((acumulador >>> 16) & 0xFF);
            saida[rodada * 4 + 2] = (byte) ((acumulador >>> 8) & 0xFF);
            saida[rodada * 4 + 3] = (byte) (acumulador & 0xFF);
        }

        return saida;
    }

    public static String base64urlEncode(byte[] buf) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    public static byte[] base64urlDecode(String str) {
        if (!str.isEmpty() && !str.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("Token contém caracteres inválidos.");
        }

        int mod = str.length() % 4;
        if (mod == 1) {
            throw new IllegalArgumentException("Comprimento de token inválido.");
        }

        String padded = mod == 0 ? str : str + "=".repeat(4 - mod);
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(padded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Token contém caracteres inválidos.");
        }

        // Canonicidade: reencoda e compara - pega bits não-canônicos no último grupo.
        if (!base64urlEncode(decoded).equals(str)) {
            throw new IllegalArgumentException("Token não está em forma canônica.");
        }

        return decoded;
    }

    public static String encrypt(String texto) {
        return encrypt(texto.getBytes(StandardCharsets.UTF_8));
    }

    public static String encrypt(byte[] textoBuf) {
        byte[] key = getKey();
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);

        byte[] encKeystream = gerarKeystream(key, iv, "enc", textoBuf.length);
        byte[] ciphertext = xorBytes(textoBuf, encKeystream);

        byte[] macKey = gerarKeystream(key, iv, "mac", TAM_BLOCO);
        byte[] integridade = checksum(concat(iv, ciphertext), macKey);

        return "FBC" + base64urlEncode(concat(concat(integridade, ciphertext), iv));
    }

    public static String decrypt(String text) {
        if (text.length() < 3 || !text.substring(0, 3).equals("FBC")) {
            throw new IllegalArgumentException("Invalid text. Text must start with FBC.");
        }

        byte[] key = getKey();
        byte[] decoded = base64urlDecode(text.substring(3));

        if (decoded.length < TAM_BLOCO + 16) {
            throw new IllegalArgumentException("Token adulterado ou chave incorreta.");
        }

        byte[] integridadeRecebida = Arrays.copyOfRange(decoded, 0, TAM_BLOCO);
        byte[] iv = Arrays.copyOfRange(decoded, decoded.length - 16, decoded.length);
        byte[] ciphertext = Arrays.copyOfRange(decoded, TAM_BLOCO, decoded.length - 16);

        byte[] macKey = gerarKeystream(key, iv, "mac", TAM_BLOCO);
        byte[] integridadeEsperada = checksum(concat(iv, ciphertext), macKey);

        if (integridadeRecebida.length != integridadeEsperada.length
                || !MessageDigest.isEqual(integridadeEsperada, integridadeRecebida)) {
            throw new IllegalArgumentException("Token adulterado ou chave incorreta.");
        }

        byte[] encKeystream = gerarKeystream(key, iv, "enc", ciphertext.length);
        return new String(xorBytes(ciphertext, encKeystream), StandardCharsets.UTF_8);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

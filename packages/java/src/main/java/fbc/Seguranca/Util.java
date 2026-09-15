package fbc.Seguranca;

import java.security.SecureRandom;
import java.util.Random;

/** Utilitários compartilhados pelos ataques (equivalentes ao Util.ts). */
public final class Util {
    private static final Random RANDOM = new SecureRandom();

    private Util() {
    }

    /** Inteiro aleatório em [min, max], inclusivo (equivalente ao random_int do PHP). */
    public static int randomInt(int min, int max) {
        return min + RANDOM.nextInt(max - min + 1);
    }

    /** N bytes aleatórios (equivalente ao random_bytes do PHP). */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }

    /** Conta quantos bits diferem entre dois buffers de mesmo tamanho. */
    public static int bitsDiferentes(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        int diff = 0;
        for (int i = 0; i < len; i++) {
            diff += contarBits1((a[i] ^ b[i]) & 0xFF);
        }
        return diff;
    }

    /** Popcount de um byte (0-255). */
    public static int contarBits1(int byteVal) {
        int x = byteVal & 0xFF;
        int count = 0;
        while (x != 0) {
            count += x & 1;
            x >>= 1;
        }
        return count;
    }

    /** Popcount total de um buffer. */
    public static int contarBitsBuffer(byte[] buf) {
        int total = 0;
        for (byte b : buf) {
            total += contarBits1(b & 0xFF);
        }
        return total;
    }

    /** Embaralha uma cópia do array (Fisher-Yates). */
    public static int[] shuffle(int[] array) {
        int[] out = array.clone();
        for (int i = out.length - 1; i > 0; i--) {
            int j = randomInt(0, i);
            int tmp = out[i];
            out[i] = out[j];
            out[j] = tmp;
        }
        return out;
    }

    /** Escolhe uma chave aleatória de um array. */
    public static String arrayRandKey(String[] keys) {
        return keys[randomInt(0, keys.length - 1)];
    }

    public static String bytesParaHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] hexParaBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex inválido.");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}

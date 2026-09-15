package fbc;

import fbc.Core.Criptografia;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.Ataques.AtaqueAvalancheChecksum;
import fbc.Seguranca.Ataques.AtaqueCanonicalizacaoToken;
import fbc.Seguranca.Ataques.AtaqueCorrelacaoMesmoPlaintext;
import fbc.Seguranca.Ataques.AtaqueFoldEstrutural;
import fbc.Seguranca.Ataques.AtaqueIntegral;
import fbc.Seguranca.Ataques.AtaqueSeparacaoChaveIV;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Harness de regressão histórica (porte de packages/node/tests/regressao_historica/regressao.js).
 *
 * Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
 * bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
 * (vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
 * PRECISA resistir (vulneravel=false).
 */
public final class RegressaoHistorica {
    private static final int TAM_BLOCO = 32;
    private static final String DIGITOS_PI =
            "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";

    private static final SecureRandom RANDOM = new SecureRandom();

    private RegressaoHistorica() {
    }

    private static int rotacaoDoRound(int roundIdx) {
        int d = DIGITOS_PI.charAt(roundIdx % DIGITOS_PI.length()) - '0';
        return (d % 7) + 1;
    }

    /** passo com mutações: bug 5 remove a reinserção da chave em cada rodada. */
    private static int[] passoComBug(
            int bug, int a, int b, byte[] keyBuf, byte[] propositoBuf, int posFib, int roundIdx) {
        int n = rotacaoDoRound(roundIdx);
        int soma = (a + b) & 0xFF;
        soma = Criptografia.rotEsquerda8(soma, n);
        soma ^= propositoBuf[posFib % propositoBuf.length] & 0xFF;
        if (bug != 5) {
            soma ^= keyBuf[(posFib + roundIdx) % keyBuf.length] & 0xFF;
        }
        soma = (soma * 131) & 0xFF;
        return new int[] {b, soma};
    }

    /** gerarKeystream com mutações: bugs 1, 2, 4, 5. */
    private static byte[] gerarKeystreamComBug(
            int bug, byte[] keyBuf, byte[] ivBuf, String proposito, int tamanho) {
        if (bug == 1) {
            // bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
            return Criptografia.gerarKeystream(keyBuf, new byte[ivBuf.length], proposito, tamanho);
        }

        int bloco = TAM_BLOCO;
        // bug 2: o colapso de metades só acontece quando a distância é exatamente
        // metade do bloco (16) — reproduzimos a condição histórica.
        int[] distancias;
        if (bug == 4) {
            distancias = new int[] {3};
        } else if (bug == 2) {
            distancias = new int[] {3, 5, 11, 19, 41, 16};
        } else {
            distancias = new int[] {3, 5, 11, 19, 41, 3, 5, 11, 19, 41};
        }
        int ivLen = ivBuf.length;
        int keyLen = keyBuf.length;
        byte[] propositoBuf = proposito.getBytes(StandardCharsets.UTF_8);

        int[] a = new int[bloco];
        int[] b = new int[bloco];
        for (int pos = 0; pos < bloco; pos++) {
            a[pos] = (keyBuf[pos % keyLen] & 0xFF) ^ (ivBuf[pos % ivLen] & 0xFF);
            b[pos] = (keyBuf[(pos + 1) % keyLen] & 0xFF) ^ (ivBuf[(pos + 1) % ivLen] & 0xFF);
        }

        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        int totalGerado = 0;
        int roundIdx = 0;
        int posFibBase = 0;

        while (totalGerado < tamanho) {
            for (int dist : distancias) {
                int[] novoB = new int[bloco];
                for (int pos = 0; pos < bloco; pos++) {
                    int[] par = passoComBug(
                            bug, a[pos], b[pos], keyBuf, propositoBuf, posFibBase + pos, roundIdx);
                    a[pos] = par[0];
                    novoB[pos] = par[1];
                }
                int[] misturado = new int[bloco];
                for (int pos = 0; pos < bloco; pos++) {
                    int vizinho = novoB[(pos + dist) % bloco];
                    if (bug == 2) {
                        // bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                        misturado[pos] = Criptografia.rotEsquerda8(novoB[pos] ^ vizinho, 1);
                    } else {
                        misturado[pos] = Criptografia.rotEsquerda8(novoB[pos], 1) ^ vizinho;
                    }
                }
                b = misturado;
                roundIdx++;
            }
            posFibBase += bloco;
            for (int pos = 0; pos < bloco; pos++) {
                saida.write(b[pos]);
            }
            totalGerado += bloco;
        }

        byte[] completo = saida.toByteArray();
        return completo.length == tamanho ? completo : Arrays.copyOf(completo, tamanho);
    }

    /** checksum com mutação: bug 3 remove a finalização. */
    private static byte[] checksumComBug(int bug, byte[] dadosBuf, byte[] keyBuf) {
        byte[] saida = new byte[32];
        int keyLen = keyBuf.length;

        for (int rodada = 0; rodada < 8; rodada++) {
            int acumulador = 0x811c9dc5 ^ (rodada * 0x01000193);

            for (int i = 0; i < dadosBuf.length; i++) {
                int byteVal = (dadosBuf[i] & 0xFF) ^ (keyBuf[(i + rodada) % keyLen] & 0xFF);
                acumulador = acumulador ^ byteVal;
                acumulador = acumulador * 16777619;
                acumulador = Criptografia.rotEsquerda32(acumulador, (i % 13) + 1);
            }

            if (bug != 3) {
                for (int k = 0; k < 3; k++) {
                    acumulador = acumulador ^ (acumulador >>> 16);
                    acumulador = acumulador * 16777619;
                    acumulador = Criptografia.rotEsquerda32(acumulador, 13);
                }
            }

            saida[rodada * 4 + 0] = (byte) ((acumulador >>> 24) & 0xFF);
            saida[rodada * 4 + 1] = (byte) ((acumulador >>> 16) & 0xFF);
            saida[rodada * 4 + 2] = (byte) ((acumulador >>> 8) & 0xFF);
            saida[rodada * 4 + 3] = (byte) (acumulador & 0xFF);
        }

        return saida;
    }

    /** base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo. */
    private static byte[] base64urlDecodeComBug(int bug, String str) {
        if (bug != 6) {
            return Criptografia.base64urlDecode(str);
        }
        String s = str.replace('-', '+').replace('_', '/').replaceAll("[^A-Za-z0-9+/=]", "");
        int mod = s.length() % 4;
        if (mod != 0) {
            s += "=".repeat(4 - mod);
        }
        return Base64.getDecoder().decode(s);
    }

    /** Alvo que aponta para a cifra com o bug selecionado. */
    static class SnapshotAlvo extends CriptografiaAlvo {
        private final int bug;

        SnapshotAlvo(int bug) {
            super();
            this.bug = bug;
        }

        @Override
        public byte[] gerarKeystreamBruto(byte[] key, byte[] iv, String proposito, int tamanho) {
            return gerarKeystreamComBug(this.bug, key, iv, proposito, tamanho);
        }

        @Override
        public byte[] checksumBruto(byte[] dados, byte[] key) {
            return checksumComBug(this.bug, dados, key);
        }

        @Override
        public byte[] base64urlDecode(String data) {
            return base64urlDecodeComBug(this.bug, data);
        }

        @Override
        public String encrypt(String texto) {
            byte[] key = this.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
            byte[] iv = new byte[16];
            RANDOM.nextBytes(iv);
            byte[] textBuf = texto.getBytes(StandardCharsets.UTF_8);

            byte[] ks = this.gerarKeystreamBruto(key, iv, "enc", textBuf.length);
            byte[] ct = new byte[textBuf.length];
            for (int i = 0; i < textBuf.length; i++) {
                ct[i] = (byte) ((textBuf[i] ^ ks[i]) & 0xFF);
            }

            byte[] macKey = this.gerarKeystreamBruto(key, iv, "mac", TAM_BLOCO);
            byte[] integridade = this.checksumBruto(Criptografia.concat(iv, ct), macKey);

            return "FBC" + Criptografia.base64urlEncode(Criptografia.concat(integridade, Criptografia.concat(ct, iv)));
        }

        @Override
        public String decrypt(String token) {
            if (token.length() < 3 || !token.substring(0, 3).equals("FBC")) {
                throw new IllegalArgumentException("prefixo");
            }
            byte[] key = this.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
            byte[] decoded = this.base64urlDecode(token.substring(3));

            byte[] integ = Arrays.copyOfRange(decoded, 0, TAM_BLOCO);
            byte[] iv = Arrays.copyOfRange(decoded, decoded.length - 16, decoded.length);
            byte[] ct = Arrays.copyOfRange(decoded, TAM_BLOCO, decoded.length - 16);

            byte[] macKey = this.gerarKeystreamBruto(key, iv, "mac", TAM_BLOCO);
            byte[] esperado = this.checksumBruto(Criptografia.concat(iv, ct), macKey);
            if (!MessageDigest.isEqual(esperado, integ)) {
                throw new IllegalArgumentException("MAC");
            }

            byte[] ks = this.gerarKeystreamBruto(key, iv, "enc", ct.length);
            byte[] out = new byte[ct.length];
            for (int i = 0; i < ct.length; i++) {
                out[i] = (byte) ((ct[i] ^ ks[i]) & 0xFF);
            }
            return new String(out, StandardCharsets.UTF_8);
        }
    }

    private static final class Caso {
        final int bug;
        final String descricao;
        final AtaqueInterface ataque;

        Caso(int bug, String descricao, AtaqueInterface ataque) {
            this.bug = bug;
            this.descricao = descricao;
            this.ataque = ataque;
        }
    }

    private static final Caso[] CASOS = {
        new Caso(1, "keystream ignora o IV", new AtaqueCorrelacaoMesmoPlaintext()),
        new Caso(2, "combinador simétrico (metades colapsam)", new AtaqueFoldEstrutural()),
        new Caso(3, "checksum sem finalização", new AtaqueAvalancheChecksum()),
        new Caso(4, "cinco rodadas de difusão", new AtaqueIntegral()),
        new Caso(5, "chave só no estado inicial", new AtaqueSeparacaoChaveIV()),
        new Caso(6, "base64 não estrito", new AtaqueCanonicalizacaoToken()),
    };

    public static void main(String[] args) {
        System.out.println("=".repeat(72));
        System.out.println("REGRESSÃO HISTÓRICA");
        System.out.println("=".repeat(72));

        int falhas = 0;
        for (Caso caso : CASOS) {
            SnapshotAlvo snapshot = new SnapshotAlvo(caso.bug);
            CriptografiaAlvo real = new CriptografiaAlvo();

            ResultadoAtaque rSnapshot;
            ResultadoAtaque rReal;
            try {
                rSnapshot = caso.ataque.executar(snapshot);
                rReal = caso.ataque.executar(real);
            } catch (Exception e) {
                System.out.println(
                        "  ❌ bug " + caso.bug + " (" + caso.descricao + "): erro — " + e.getMessage());
                falhas++;
                continue;
            }

            boolean detectou = rSnapshot.vulneravel();
            boolean resistiu = !rReal.vulneravel();
            boolean ok = detectou && resistiu;
            if (!ok) {
                falhas++;
            }

            System.out.println(
                    "  " + (ok ? "✅" : "❌") + " bug " + caso.bug + " (" + caso.descricao + "): "
                            + "snapshot " + (detectou ? "detectado" : "NÃO detectado")
                            + " | atual " + (resistiu ? "resistiu" : "ACUSOU"));

            if (!ok) {
                System.out.println("       snapshot: " + rSnapshot.linhaResumo());
                System.out.println("       atual:    " + rReal.linhaResumo());
            }
        }

        System.out.println("=".repeat(72));
        if (falhas == 0) {
            System.out.println("RESUMO: " + CASOS.length
                    + " bugs históricos detectados; código atual resiste a todos.");
        } else {
            System.out.println("RESUMO: " + falhas + " caso(s) falharam.");
        }
        System.out.println("=".repeat(72));

        System.exit(falhas == 0 ? 0 : 1);
    }
}

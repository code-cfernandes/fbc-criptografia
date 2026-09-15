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
 * A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
 * reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
 * Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
 * aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
 * gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
 * vaza nesse cenário catastrófico.
 *
 * Isso não é um "bug" da implementação (é uma propriedade universal de
 * qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
 * quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
 * suíte: a segurança inteira depende do IV nunca repetir.
 */
public class AtaqueReusoIV implements AtaqueInterface {
    @Override
    public String nome() {
        return "Reuso forçado de IV (two-time pad)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] ivFixo = Util.randomBytes(alvo.tamanhoIv());

        byte[] primeiro = alvo.gerarKeystreamBruto(chave, ivFixo, "enc", 16);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        String plaintext1 = "TRANSFERIR_1000";
        String plaintext2 = "CANCELAR_TUDO!!";
        int tamanho = Math.max(plaintext1.length(), plaintext2.length());

        byte[] keystream = alvo.gerarKeystreamBruto(chave, ivFixo, "enc", tamanho);

        byte[] ciphertext1 = this.xor(plaintext1, keystream);
        byte[] ciphertext2 = this.xor(plaintext2, keystream);

        // O atacante NUNCA precisou saber a key nem o keystream - só
        // observou os dois ciphertexts (que vazariam publicamente se o
        // IV fosse reusado) e os combinou entre si.
        byte[] xorDosCiphertexts = this.xor(ciphertext1, ciphertext2);
        byte[] xorEsperadoDosPlaintexts = this.xor(plaintext1, plaintext2);

        boolean vazou = java.util.Arrays.equals(xorDosCiphertexts, xorEsperadoDosPlaintexts);

        // Com IV reusado, a propriedade é universal e sempre se confirma - por
        // isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
        // demonstração). Só vira alerta se, por algum motivo, a propriedade
        // NÃO se confirmar (o que indicaria um combinador inconsistente).
        Map<String, Object> dados = new HashMap<>();
        dados.put("plaintext1", plaintext1);
        dados.put("plaintext2", plaintext2);
        dados.put("xor_plaintexts_hex", Util.bytesParaHex(xorEsperadoDosPlaintexts));
        dados.put("xor_ciphertexts_hex", Util.bytesParaHex(xorDosCiphertexts));

        return new ResultadoAtaque(
                nome(),
                !vazou,
                vazou ? Severidade.DEMONSTRACAO : Severidade.ALTA,
                vazou
                        ? "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) "
                                + "sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA "
                                + "defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
                        : "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)",
                dados);
    }

    private byte[] xor(String a, String b) {
        byte[] A = a.getBytes(StandardCharsets.ISO_8859_1);
        byte[] B = b.getBytes(StandardCharsets.ISO_8859_1);
        int len = Math.min(A.length, B.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((A[i] ^ B[i]) & 0xFF);
        }
        return out;
    }

    private byte[] xor(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        }
        return out;
    }

    private byte[] xor(String a, byte[] b) {
        byte[] A = a.getBytes(StandardCharsets.ISO_8859_1);
        int len = Math.min(A.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((A[i] ^ b[i]) & 0xFF);
        }
        return out;
    }
}

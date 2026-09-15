package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CamposToken;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
 * ambíguo, um atacante pode reordenar/deslocar os campos e construir um
 * token que sistemas diferentes interpretam de formas diferentes. Todos os
 * rearranjos devem ser rejeitados pela integridade.
 */
public class AtaqueConfusaoCampos implements AtaqueInterface {
    @Override
    public String nome() {
        return "Confusão de campos do token (reordenação/deslocamento)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_encode/decode do alvo.");
        }

        String texto = "MENSAGEM_PARA_TESTE_DE_CAMPOS";
        String token = alvo.encrypt(texto);
        String prefixo = alvo.prefixo();
        CamposToken campos = alvo.decompor(alvo.base64urlDecode(token.substring(prefixo.length())));

        byte[] integridade = campos.integridade;
        byte[] ciphertext = campos.ciphertext;
        byte[] iv = campos.iv;

        byte[] ultimoCipher = new byte[] {ciphertext[ciphertext.length - 1]};
        byte[] ivReverso = iv.clone();
        for (int i = 0; i < ivReverso.length / 2; i++) {
            byte tmp = ivReverso[i];
            ivReverso[i] = ivReverso[ivReverso.length - 1 - i];
            ivReverso[ivReverso.length - 1 - i] = tmp;
        }

        Map<String, byte[]> variantes = new LinkedHashMap<>();
        variantes.put("iv no início", concat(iv, integridade, ciphertext));
        variantes.put("ciphertext antes da integridade", concat(ciphertext, integridade, iv));
        variantes.put("iv duplicado no fim", concat(integridade, ciphertext, iv, iv));
        variantes.put(
                "integridade encurtada", concat(java.util.Arrays.copyOfRange(integridade, 1, integridade.length), ciphertext, iv));
        variantes.put("byte extra no início", concat(new byte[] {'X'}, integridade, ciphertext, iv));
        variantes.put(
                "byte extra entre integridade e ciphertext",
                concat(integridade, new byte[] {'X'}, ciphertext, iv));
        variantes.put("byte extra antes do iv", concat(integridade, ciphertext, new byte[] {'X'}, iv));
        variantes.put("iv rotacionado", concat(integridade, ciphertext, ivReverso));
        variantes.put(
                "iv e último byte do ciphertext trocados",
                concat(
                        integridade,
                        java.util.Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 1),
                        iv,
                        ultimoCipher));

        List<String> aceitas = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : variantes.entrySet()) {
            String tokenVariante = prefixo + alvo.base64urlEncode(e.getValue());
            try {
                String r = alvo.decrypt(tokenVariante);
                aceitas.add(e.getKey() + " -> aceito (retornou " + r.getBytes(StandardCharsets.UTF_8).length
                        + " bytes)");
            } catch (Exception ex) {
                // esperado
            }
        }

        if (!aceitas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    aceitas.size() + " rearranjo(s) de campo foram aceitos",
                    Map.of("exemplos", aceitas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todos os " + variantes.size() + " rearranjos de campo foram rejeitados");
    }

    private static byte[] concat(byte[]... partes) {
        int total = 0;
        for (byte[] p : partes) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : partes) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}

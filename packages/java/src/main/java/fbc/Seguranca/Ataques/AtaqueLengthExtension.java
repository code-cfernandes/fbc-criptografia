package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CamposToken;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Length extension / truncamento: a estrutura do token é
 * integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
 * Truncar, estender ou deslocar bytes não pode produzir um token aceito.
 */
public class AtaqueLengthExtension implements AtaqueInterface {
    private final String mensagem;

    public AtaqueLengthExtension() {
        this("texto para o ataque de length extension");
    }

    public AtaqueLengthExtension(String mensagem) {
        this.mensagem = mensagem;
    }

    @Override
    public String nome() {
        return "Length extension / truncamento de token";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        String prefixo = alvo.prefixo();
        String token = alvo.encrypt(this.mensagem);
        String corpo = token.substring(prefixo.length());
        int meio = corpo.length() / 2;

        Map<String, String> variantes = new LinkedHashMap<>();
        variantes.put("append A", prefixo + corpo + "A");
        variantes.put("append =", prefixo + corpo + "=");
        variantes.put("truncar 1 char", prefixo + corpo.substring(0, corpo.length() - 1));
        variantes.put("truncar 2 chars", prefixo + corpo.substring(0, corpo.length() - 2));
        variantes.put(
                "inserir ! no meio", prefixo + corpo.substring(0, meio) + "!" + corpo.substring(meio));
        variantes.put("prefixo extra", prefixo + "A" + corpo);

        // variantes que mexem nos campos decodificados
        try {
            byte[] decoded = alvo.base64urlDecode(corpo);
            CamposToken campos = alvo.decompor(decoded);

            byte[] ctMaior = concat(campos.ciphertext, new byte[] {0x41});
            variantes.put(
                    "ciphertext +1 byte",
                    prefixo + alvo.base64urlEncode(
                            alvo.recompor(new CamposToken(campos.integridade, ctMaior, campos.iv))));

            byte[] ctMenor = Arrays.copyOfRange(
                    campos.ciphertext, 0, Math.max(0, campos.ciphertext.length - 1));
            variantes.put(
                    "ciphertext -1 byte",
                    prefixo + alvo.base64urlEncode(
                            alvo.recompor(new CamposToken(campos.integridade, ctMenor, campos.iv))));

            byte[] ivMaior = concat(campos.iv, new byte[] {0x42});
            variantes.put(
                    "iv +1 byte",
                    prefixo + alvo.base64urlEncode(
                            alvo.recompor(new CamposToken(campos.integridade, campos.ciphertext, ivMaior))));
        } catch (Exception e) {
            // se a decodificação falhar, segue com as variantes textuais
        }

        List<String> aceitas = new ArrayList<>();
        for (Map.Entry<String, String> e : variantes.entrySet()) {
            if (e.getValue().equals(token)) {
                continue;
            }
            try {
                alvo.decrypt(e.getValue());
                aceitas.add(e.getKey());
            } catch (Exception ex) {
                // esperado
            }
        }

        boolean vulneravel = !aceitas.isEmpty();

        Map<String, Object> dados = new java.util.HashMap<>();
        dados.put("aceitas", aceitas);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                vulneravel
                        ? aceitas.size() + " variante(s) aceita(s): " + String.join("; ", aceitas)
                        : "Todas as " + variantes.size()
                                + " variantes de truncamento/extensão foram rejeitadas",
                dados);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Um mesmo token não deveria ter múltiplas representações textuais válidas.
 * Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
 * padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
 * lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
 * token. Isso é "token smuggling": sistemas que comparam/usam a string do
 * token de formas diferentes (cache, WAF, deduplicação/replay) discordam
 * sobre o que ele significa.
 */
public class AtaqueCanonicalizacaoToken implements AtaqueInterface {
    @Override
    public String nome() {
        return "Canonicalização do token (base64 não-canônico)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_encode/decode do alvo.");
        }

        String texto = "MENSAGEM_DE_TESTE_DE_CANONICALIZACAO";
        String token = alvo.encrypt(texto);
        String prefixo = alvo.prefixo();
        String corpo = token.substring(prefixo.length());
        int meio = corpo.length() / 2;

        Map<String, String> variantes = new LinkedHashMap<>();
        int[] posicoes = {0, meio, corpo.length() - 1};
        for (int p : posicoes) {
            variantes.put("espaço na posição " + p, prefixo + corpo.substring(0, p) + " " + corpo.substring(p));
            variantes.put("newline na posição " + p, prefixo + corpo.substring(0, p) + "\n" + corpo.substring(p));
            variantes.put("tab na posição " + p, prefixo + corpo.substring(0, p) + "\t" + corpo.substring(p));
        }
        variantes.put("alfabeto padrão (+/)", prefixo + corpo.replace('-', '+').replace('_', '/'));
        variantes.put("padding \"=\" extra", prefixo + corpo + "=");
        variantes.put(
                "caractere inválido no meio", prefixo + corpo.substring(0, meio) + "!" + corpo.substring(meio));

        List<String> aceitas = new ArrayList<>();
        for (Map.Entry<String, String> e : variantes.entrySet()) {
            String v = e.getValue();
            if (v.equals(token)) {
                continue;
            }
            try {
                if (alvo.decrypt(v).equals(texto)) {
                    aceitas.add(e.getKey());
                }
            } catch (Exception ex) {
                // esperado
            }
        }

        if (!aceitas.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.MEDIA,
                    aceitas.size()
                            + " variante(s) textualmente diferente(s) decifram para o mesmo texto: "
                            + String.join("; ", aceitas),
                    Map.of("variantes_aceitas", aceitas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todas as " + variantes.size() + " variantes não-canônicas foram rejeitadas");
    }
}

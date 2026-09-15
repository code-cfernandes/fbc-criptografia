package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Robustez do parser de tokens: qualquer entrada que não seja um token
 * íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
 * devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
 * é uma porta pra bugs de validação e "token smuggling".
 */
public class AtaqueTokensMalformados implements AtaqueInterface {
    @Override
    public String nome() {
        return "Tokens malformados (fuzzing de entrada)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        String token = alvo.encrypt("MENSAGEM_VALIDA_PARA_TESTE");
        String prefixo = alvo.prefixo();
        String corpo = token.substring(prefixo.length());

        Map<String, String> casos = new LinkedHashMap<>();
        casos.put("vazio", "");
        casos.put("só prefixo", prefixo);
        casos.put("prefixo errado", "XXX" + corpo);
        casos.put("base64 inválido", prefixo + "!!!@@@###");
        casos.put("bytes extras no fim", token + "AAAA");
        casos.put("bytes extras no início", "AAAA" + token);
        for (int len = 1; len < token.length(); len++) {
            casos.put("truncado em " + len, token.substring(0, len));
        }
        for (int i = 0; i < 20; i++) {
            casos.put("lixo aleatório " + i, prefixo + Util.bytesParaHex(Util.randomBytes(16)));
        }

        List<String> aceitos = new ArrayList<>();
        for (Map.Entry<String, String> e : casos.entrySet()) {
            try {
                String r = alvo.decrypt(e.getValue());
                aceitos.add(e.getKey() + " -> aceito (retornou "
                        + r.getBytes(StandardCharsets.UTF_8).length + " bytes)");
            } catch (Exception ex) {
                // comportamento esperado
            }
        }

        if (!aceitos.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    aceitos.size() + " entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas",
                    Map.of("exemplos", aceitos.subList(0, Math.min(10, aceitos.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todas as " + casos.size() + " entradas malformadas foram rejeitadas");
    }
}

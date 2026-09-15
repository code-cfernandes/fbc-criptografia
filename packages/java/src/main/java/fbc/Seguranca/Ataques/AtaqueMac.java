package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CamposToken;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
 * (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
 * Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
 */
public class AtaqueMac implements AtaqueInterface {
    private final String mensagem;

    public AtaqueMac() {
        this("mensagem para o ataque de MAC");
    }

    public AtaqueMac(String mensagem) {
        this.mensagem = mensagem;
    }

    @Override
    public String nome() {
        return "Força bruta e truncamento do MAC";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        String token = alvo.encrypt(this.mensagem);
        byte[] decoded = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
        CamposToken campos = alvo.decompor(decoded);

        List<String> aceitos = new ArrayList<>();

        // 1) integridade zerada
        try {
            alvo.decrypt(this.montar(alvo, campos, new byte[campos.integridade.length]));
            aceitos.add("integridade zerada");
        } catch (Exception e) {
            // esperado
        }

        // 2) integridade truncada pela metade
        try {
            alvo.decrypt(this.montar(
                    alvo, campos, java.util.Arrays.copyOfRange(campos.integridade, 0, 16)));
            aceitos.add("integridade truncada (16 bytes)");
        } catch (Exception e) {
            // esperado
        }

        // 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
        // que reconstruiria o próprio token válido e não é uma forja)
        byte[] base = campos.integridade.clone();
        int original = base[0] & 0xFF;
        for (int v = 0; v < 256; v++) {
            if (v == original) {
                continue;
            }
            byte[] tentativa = base.clone();
            tentativa[0] = (byte) v;
            try {
                alvo.decrypt(this.montar(alvo, campos, tentativa));
                aceitos.add("byte 0 do MAC = " + v);
            } catch (Exception e) {
                // esperado
            }
        }

        boolean vulneravel = !aceitos.isEmpty();

        Map<String, Object> dados = new HashMap<>();
        dados.put("aceitos", aceitos);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                vulneravel
                        ? aceitos.size() + " variante(s) de MAC aceitas: "
                                + String.join("; ", aceitos.subList(0, Math.min(5, aceitos.size())))
                        : "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita",
                dados);
    }

    private String montar(AlvoCriptografico alvo, CamposToken campos, byte[] integridade) {
        CamposToken alterado = new CamposToken(integridade, campos.ciphertext, campos.iv);
        return alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(alterado));
    }
}

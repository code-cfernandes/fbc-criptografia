package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CamposToken;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.ArrayList;
import java.util.List;

/**
 * O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
 * token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
 * sucesso", a cifra não está autenticando o conteúdo.
 */
public class AtaqueAdulteracao implements AtaqueInterface {
    private static final String[] CAMPOS = {"integridade", "ciphertext", "iv"};

    private final int tentativas;

    public AtaqueAdulteracao() {
        this(500);
    }

    public AtaqueAdulteracao(int tentativas) {
        this.tentativas = tentativas;
    }

    @Override
    public String nome() {
        return "Adulteração de bits (integridade)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_encode/decode do alvo.");
        }

        List<String> aceitosIndevidamente = new ArrayList<>();

        for (int t = 0; t < this.tentativas; t++) {
            String texto = "MSG_" + t + "X".repeat(Util.randomInt(0, 50));
            String token = alvo.encrypt(texto);
            byte[] decodificado = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
            CamposToken campos = alvo.decompor(decodificado);

            String nomeCampo = Util.arrayRandKey(CAMPOS);
            byte[] valor = campo(campos, nomeCampo).clone();
            if (valor.length == 0) {
                continue;
            }
            int pos = Util.randomInt(0, valor.length - 1);
            valor[pos] = (byte) (valor[pos] ^ (1 << Util.randomInt(0, 7)));
            definirCampo(campos, nomeCampo, valor);

            String tokenAdulterado = alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(campos));

            try {
                String resultado = alvo.decrypt(tokenAdulterado);
                aceitosIndevidamente.add(
                        "campo=" + nomeCampo + ", texto original=" + texto + ", resultado aceito=" + resultado);
            } catch (Exception e) {
                // esperado - a adulteração deveria ser rejeitada
            }
        }

        if (!aceitosIndevidamente.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    aceitosIndevidamente.size() + " de " + this.tentativas
                            + " tokens adulterados foram ACEITOS");
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todas as " + this.tentativas + " adulterações foram rejeitadas");
    }

    private static byte[] campo(CamposToken campos, String nome) {
        switch (nome) {
            case "integridade":
                return campos.integridade;
            case "ciphertext":
                return campos.ciphertext;
            case "iv":
                return campos.iv;
            default:
                throw new IllegalArgumentException("Campo desconhecido: " + nome);
        }
    }

    private static void definirCampo(CamposToken campos, String nome, byte[] valor) {
        switch (nome) {
            case "integridade":
                campos.integridade = valor;
                break;
            case "ciphertext":
                campos.ciphertext = valor;
                break;
            case "iv":
                campos.iv = valor;
                break;
            default:
                throw new IllegalArgumentException("Campo desconhecido: " + nome);
        }
    }
}

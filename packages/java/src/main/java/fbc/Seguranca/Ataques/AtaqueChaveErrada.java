package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.ArrayList;
import java.util.List;

/**
 * Garante que um token só decifra com a chave correta: com qualquer outra chave
 * de 32 bytes, decrypt() tem que lançar.
 *
 * A chave original é restaurada no final pra não afetar os outros ataques.
 */
public class AtaqueChaveErrada implements AtaqueInterface {
    private final int tentativas;

    public AtaqueChaveErrada() {
        this(30);
    }

    public AtaqueChaveErrada(int tentativas) {
        this.tentativas = tentativas;
    }

    @Override
    public String nome() {
        return "Rejeição de chave incorreta";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de CriptografiaAlvo para trocar a chave.");
        }

        String chaveOriginal = alvo.chaveDeTeste();

        List<String> tokens = new ArrayList<>();
        for (int i = 0; i < this.tentativas; i++) {
            tokens.add(alvo.encrypt("MENSAGEM_SECRETA_" + i));
        }

        List<String> aceitos = new ArrayList<>();
        try {
            for (int i = 0; i < tokens.size(); i++) {
                new CriptografiaAlvo(Util.bytesParaHex(Util.randomBytes(16)));
                try {
                    String r = alvo.decrypt(tokens.get(i));
                    aceitos.add("tentativa " + i + " aceitou (retornou " + r + ")");
                } catch (Exception e) {
                    // esperado
                }
            }
        } finally {
            new CriptografiaAlvo(chaveOriginal);
        }

        if (!aceitos.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    aceitos.size() + " de " + this.tentativas
                            + " tokens foram aceitos com a chave errada");
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Nenhum dos " + this.tentativas + " tokens foi aceito com chave incorreta");
    }
}

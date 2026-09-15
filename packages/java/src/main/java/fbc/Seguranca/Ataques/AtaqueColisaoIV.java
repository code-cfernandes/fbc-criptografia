package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.HashSet;
import java.util.Set;

/**
 * Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as garantias
 * de confidencialidade (keystream reusado = "two-time pad"). Gera muitos tokens
 * do MESMO texto e verifica se os IVs nunca colidem.
 */
public class AtaqueColisaoIV implements AtaqueInterface {
    private final int geracoes;

    public AtaqueColisaoIV() {
        this(5000);
    }

    public AtaqueColisaoIV(int geracoes) {
        this.geracoes = geracoes;
    }

    @Override
    public String nome() {
        return "Colisão de IV";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_decode do alvo.");
        }

        Set<String> vistos = new HashSet<>();
        int colisoes = 0;

        for (int i = 0; i < this.geracoes; i++) {
            String token = alvo.encrypt("MESMO_TEXTO_SEMPRE");
            byte[] decodificado = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
            String chaveIv = Util.bytesParaHex(alvo.decompor(decodificado).iv);
            if (vistos.contains(chaveIv)) {
                colisoes++;
            }
            vistos.add(chaveIv);
        }

        if (colisoes > 0) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    colisoes + " colisão(ões) de IV em " + this.geracoes + " gerações");
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "0 colisões em " + this.geracoes + " gerações");
    }
}

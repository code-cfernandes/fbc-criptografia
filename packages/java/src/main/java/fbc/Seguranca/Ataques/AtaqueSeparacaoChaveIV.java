package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
 * Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
 * resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
 *
 *     keystream(key, iv) == keystream(key ^ d, iv ^ d)
 *
 * para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
 * propriedade estrutural relevante: significa que key e iv não entram de
 * forma independente na cifra, o que enfraquece o modelo de segurança (o IV
 * deveria contribuir com entropia própria, não só deslocar a chave por XOR).
 */
public class AtaqueSeparacaoChaveIV implements AtaqueInterface {
    private final int tentativas;
    private final int tamanhoBloco;

    public AtaqueSeparacaoChaveIV() {
        this(50, 32);
    }

    public AtaqueSeparacaoChaveIV(int tentativas, int tamanhoBloco) {
        this.tentativas = tentativas;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Separação chave/IV (invariância a key XOR iv)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int tamChave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;
        int tamIv = alvo.tamanhoIv();

        byte[] primeiro = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8),
                Util.randomBytes(tamIv),
                "enc",
                this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        int confirmacoes = 0;
        for (int t = 0; t < this.tentativas; t++) {
            byte[] chave = Util.randomBytes(tamChave);
            byte[] iv = Util.randomBytes(tamIv);
            byte[] d = Util.randomBytes(tamIv);

            byte[] chave2 = new byte[tamChave];
            for (int p = 0; p < tamChave; p++) {
                chave2[p] = (byte) ((chave[p] ^ d[p % tamIv]) & 0xFF);
            }
            byte[] iv2 = new byte[tamIv];
            for (int p = 0; p < tamIv; p++) {
                iv2[p] = (byte) ((iv[p] ^ d[p]) & 0xFF);
            }

            byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanhoBloco);
            byte[] ks2 = alvo.gerarKeystreamBruto(chave2, iv2, "enc", this.tamanhoBloco);

            if (Arrays.equals(ks1, ks2)) {
                confirmacoes++;
            }
        }

        boolean invariante = confirmacoes == this.tentativas;

        Map<String, Object> dados = new HashMap<>();
        dados.put("confirmacoes", confirmacoes);
        dados.put("tentativas", this.tentativas);

        return new ResultadoAtaque(
                nome(),
                invariante,
                invariante ? Severidade.MEDIA : Severidade.INFO,
                invariante
                        ? "Confirmado em " + this.tentativas + "/" + this.tentativas
                                + ": keystream(key,iv) == keystream(key^d, iv^d). "
                                + "O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule."
                        : "Invariância não se confirmou (" + confirmacoes + "/" + this.tentativas
                                + "); key e iv entram de forma independente.",
                dados);
    }
}

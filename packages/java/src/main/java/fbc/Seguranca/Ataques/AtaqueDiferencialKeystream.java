package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
 * IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
 * boa, essas diferenças são uniformes e únicas. Sinaliza:
 *  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
 *  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
 *    que é o insumo básico de um ataque diferencial.
 */
public class AtaqueDiferencialKeystream implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;

    public AtaqueDiferencialKeystream() {
        this(2000, 32);
    }

    public AtaqueDiferencialKeystream(int amostras, int tamanhoBloco) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
    }

    @Override
    public String nome() {
        return "Diferencial do keystream (delta fixo no IV)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = Util.randomBytes(alvo.chaveDeTeste().length());
        int tamanhoIv = alvo.tamanhoIv();
        byte[] primeiro = alvo.gerarKeystreamBruto(
                chave, Util.randomBytes(tamanhoIv), "enc", this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        byte[] delta = new byte[tamanhoIv];
        delta[Util.randomInt(0, tamanhoIv - 1)] = (byte) (1 << Util.randomInt(0, 7));

        int totalBits = this.tamanhoBloco * 8;
        boolean[] sempreZero = new boolean[totalBits];
        boolean[] sempreUm = new boolean[totalBits];
        for (int i = 0; i < totalBits; i++) {
            sempreZero[i] = true;
            sempreUm[i] = true;
        }
        Set<String> deltas = new HashSet<>();

        for (int i = 0; i < this.amostras; i++) {
            byte[] iv = Util.randomBytes(tamanhoIv);
            byte[] iv2 = this.xorBytes(iv, delta);

            byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanhoBloco);
            byte[] ks2 = alvo.gerarKeystreamBruto(chave, iv2, "enc", this.tamanhoBloco);
            byte[] d = this.xorBytes(ks1, ks2);
            deltas.add(Util.bytesParaHex(d));

            for (int p = 0; p < d.length; p++) {
                int b = d[p] & 0xFF;
                for (int bit = 0; bit < 8; bit++) {
                    int idx = p * 8 + bit;
                    if (((b >> bit) & 1) == 1) {
                        sempreZero[idx] = false;
                    } else {
                        sempreUm[idx] = false;
                    }
                }
            }
        }

        int bitsFixos = 0;
        for (int idx = 0; idx < totalBits; idx++) {
            if (sempreZero[idx] || sempreUm[idx]) {
                bitsFixos++;
            }
        }
        int colisoes = this.amostras - deltas.size();

        boolean vulneravel = bitsFixos > 0 || colisoes > 0;

        Map<String, Object> dados = new HashMap<>();
        dados.put("bits_fixos", bitsFixos);
        dados.put("colisoes", colisoes);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                "delta de 1 bit no IV: " + bitsFixos + " bit(s) de saída fixo(s), " + colisoes
                        + " diferencial(is) repetido(s) em " + this.amostras + " amostras",
                dados);
    }

    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        }
        return out;
    }
}

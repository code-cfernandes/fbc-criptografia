package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * BIC (Bit Independence Criterion): pares de bits de saída não devem estar
 * correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
 * e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
 * cada par de bits de saída. Pares muito correlacionados indicam difusão
 * acoplada (um bit "carrega" informação sobre outro).
 */
public class AtaqueBIC implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int amostras;
    private final double limite;

    public AtaqueBIC() {
        this(32, 300, 0.35);
    }

    public AtaqueBIC(int tamanhoBloco, int amostras, double limite) {
        this.tamanhoBloco = tamanhoBloco;
        this.amostras = amostras;
        this.limite = limite;
    }

    @Override
    public String nome() {
        return "BIC (Bit Independence Criterion)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int totalBits = this.tamanhoBloco * 8;
        int tamanhoIv = alvo.tamanhoIv();

        int[][] amostrasFlips = new int[this.amostras][totalBits];
        for (int s = 0; s < this.amostras; s++) {
            byte[] iv1 = Util.randomBytes(tamanhoIv);
            byte[] iv2 = iv1.clone();
            int pos = Util.randomInt(0, tamanhoIv - 1);
            iv2[pos] = (byte) (iv2[pos] ^ (1 << Util.randomInt(0, 7)));

            byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv1, "enc", this.tamanhoBloco);
            byte[] ks2 = alvo.gerarKeystreamBruto(chave, iv2, "enc", this.tamanhoBloco);

            for (int j = 0; j < totalBits; j++) {
                int b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
                int b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
                amostrasFlips[s][j] = b1 != b2 ? 1 : 0;
            }
        }

        double piorPhi = 0;
        int[] piorPar = {-1, -1};
        int n = this.amostras;

        for (int a = 0; a < totalBits; a++) {
            for (int b = a + 1; b < totalBits; b++) {
                int n11 = 0;
                int n10 = 0;
                int n01 = 0;
                int n00 = 0;
                for (int s = 0; s < n; s++) {
                    int fa = amostrasFlips[s][a];
                    int fb = amostrasFlips[s][b];
                    if (fa == 1 && fb == 1) {
                        n11++;
                    } else if (fa == 1 && fb == 0) {
                        n10++;
                    } else if (fa == 0 && fb == 1) {
                        n01++;
                    } else {
                        n00++;
                    }
                }
                double den = Math.sqrt((double) (n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00));
                double phi = den > 0 ? (n11 * n00 - n10 * n01) / den : 0;
                if (Math.abs(phi) > Math.abs(piorPhi)) {
                    piorPhi = phi;
                    piorPar = new int[] {a, b};
                }
            }
        }

        boolean vulneravel = Math.abs(piorPhi) > this.limite;

        Map<String, Object> dados = new HashMap<>();
        dados.put("pior_phi", piorPhi);
        dados.put("par", new int[] {piorPar[0], piorPar[1]});

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "maior |phi|=%.3f entre bits de saída [%d, %d] (limite %.2f); %d amostras",
                        Math.abs(piorPhi),
                        piorPar[0],
                        piorPar[1],
                        this.limite,
                        n),
                dados);
    }
}

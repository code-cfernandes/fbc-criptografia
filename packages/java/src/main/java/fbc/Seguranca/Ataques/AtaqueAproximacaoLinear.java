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
 * Aproximação linear (criptoanálise de Matsui): procura por correlação entre
 * bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
 * aproximação linear com viés relevante; bias alto é uma pista explorável.
 */
public class AtaqueAproximacaoLinear implements AtaqueInterface {
    private final int amostras;
    private final int tamanhoBloco;
    private final double limiteBias;

    public AtaqueAproximacaoLinear() {
        this(200, 32, 0.3);
    }

    public AtaqueAproximacaoLinear(int amostras, int tamanhoBloco, double limiteBias) {
        this.amostras = amostras;
        this.tamanhoBloco = tamanhoBloco;
        this.limiteBias = limiteBias;
    }

    @Override
    public String nome() {
        return "Aproximação linear (viés de Walsh)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int tamIv = alvo.tamanhoIv();
        int bitsEntrada = tamIv * 8;
        int bitsSaida = this.tamanhoBloco * 8;
        int lenChave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;

        int[][] entradas = new int[this.amostras][bitsEntrada];
        int[][] saidas = new int[this.amostras][bitsSaida];

        for (int s = 0; s < this.amostras; s++) {
            byte[] chave = Util.randomBytes(lenChave);
            byte[] iv = Util.randomBytes(tamIv);
            byte[] ks = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanhoBloco);

            for (int j = 0; j < bitsEntrada; j++) {
                entradas[s][j] = (iv[j >> 3] >> (7 - (j & 7))) & 1;
            }
            for (int j = 0; j < bitsSaida; j++) {
                saidas[s][j] = (ks[j >> 3] >> (7 - (j & 7))) & 1;
            }
        }

        double maiorBias = 0;
        int[] par = {-1, -1};
        for (int i = 0; i < bitsEntrada; i++) {
            for (int j = 0; j < bitsSaida; j++) {
                int iguais = 0;
                for (int s = 0; s < this.amostras; s++) {
                    if (entradas[s][i] == saidas[s][j]) {
                        iguais++;
                    }
                }
                double bias = Math.abs((double) iguais / this.amostras - 0.5);
                if (bias > maiorBias) {
                    maiorBias = bias;
                    par = new int[] {i, j};
                }
            }
        }

        boolean vulneravel = maiorBias > this.limiteBias;

        Map<String, Object> dados = new HashMap<>();
        dados.put("maior_bias", maiorBias);
        dados.put("par", new int[] {par[0], par[1]});

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.ALTA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "maior viés |p-0.5|=%.4f na aproximação IV[bit %d] -> saída[bit %d] (limite %.2f); %d amostras",
                        maiorBias,
                        par[0],
                        par[1],
                        this.limiteBias,
                        this.amostras),
                dados);
    }
}

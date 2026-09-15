package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
 * o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
 * posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
 */
public class AtaqueCoberturaDependenciaIV implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int perturbacoesPorPosicao;

    public AtaqueCoberturaDependenciaIV() {
        this(32, 5);
    }

    public AtaqueCoberturaDependenciaIV(int tamanhoBloco, int perturbacoesPorPosicao) {
        this.tamanhoBloco = tamanhoBloco;
        this.perturbacoesPorPosicao = perturbacoesPorPosicao;
    }

    @Override
    public String nome() {
        return "Cobertura de dependência do IV (entrada x saída)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        int tamanhoIv = alvo.tamanhoIv();
        byte[] ivBase = new byte[tamanhoIv];

        byte[] ksBase = alvo.gerarKeystreamBruto(chave, ivBase, "enc", this.tamanhoBloco);
        if (ksBase == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        List<String> paresIndependentes = new ArrayList<>();

        for (int posIv = 0; posIv < tamanhoIv; posIv++) {
            boolean[] afetou = new boolean[this.tamanhoBloco];

            for (int p = 0; p < this.perturbacoesPorPosicao; p++) {
                byte[] iv = ivBase.clone();
                iv[posIv] = (byte) Util.randomInt(1, 255);
                byte[] ks = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanhoBloco);

                for (int posSaida = 0; posSaida < this.tamanhoBloco; posSaida++) {
                    if (ks[posSaida] != ksBase[posSaida]) {
                        afetou[posSaida] = true;
                    }
                }
            }

            for (int posSaida = 0; posSaida < this.tamanhoBloco; posSaida++) {
                if (!afetou[posSaida]) {
                    paresIndependentes.add("iv[" + posIv + "] -> saida[" + posSaida + "]");
                }
            }
        }

        if (!paresIndependentes.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.ALTA,
                    paresIndependentes.size() + " par(es) sem dependência detectável em "
                            + this.perturbacoesPorPosicao + " tentativas cada",
                    Map.of("pares", paresIndependentes.subList(0, Math.min(20, paresIndependentes.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todas as " + tamanhoIv + " posições do IV influenciam todas as " + this.tamanhoBloco
                        + " posições de saída");
    }
}

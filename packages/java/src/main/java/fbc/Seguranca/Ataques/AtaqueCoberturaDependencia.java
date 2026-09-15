package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
 * de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
 * pra evitar falso-positivo por coincidência de valor). Uma dependência
 * ausente indica que a mistura não se propagou completamente - um atacante
 * poderia isolar e atacar aquele par de posições separadamente do resto.
 */
public class AtaqueCoberturaDependencia implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int perturbacoesPorPar;

    public AtaqueCoberturaDependencia() {
        this(32, 5);
    }

    public AtaqueCoberturaDependencia(int tamanhoBloco, int perturbacoesPorPar) {
        this.tamanhoBloco = tamanhoBloco;
        this.perturbacoesPorPar = perturbacoesPorPar;
    }

    @Override
    public String nome() {
        return "Cobertura de dependência (matriz entrada x saída)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int tamanho = this.tamanhoBloco;
        byte[] chaveBase = new byte[tamanho];
        byte[] iv = Util.randomBytes(alvo.tamanhoIv());

        byte[] ksBase = alvo.gerarKeystreamBruto(chaveBase, iv, "enc", tamanho);
        if (ksBase == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        List<String> paresIndependentes = new ArrayList<>();

        for (int posEntrada = 0; posEntrada < tamanho; posEntrada++) {
            boolean[] afetouAlgumaSaida = new boolean[tamanho];

            for (int p = 0; p < this.perturbacoesPorPar; p++) {
                byte[] chaveTeste = chaveBase.clone();
                chaveTeste[posEntrada] = (byte) Util.randomInt(1, 255);
                byte[] ks = alvo.gerarKeystreamBruto(chaveTeste, iv, "enc", tamanho);

                for (int posSaida = 0; posSaida < tamanho; posSaida++) {
                    if (ks[posSaida] != ksBase[posSaida]) {
                        afetouAlgumaSaida[posSaida] = true;
                    }
                }
            }

            for (int posSaida = 0; posSaida < tamanho; posSaida++) {
                if (!afetouAlgumaSaida[posSaida]) {
                    paresIndependentes.add("entrada[" + posEntrada + "] -> saída[" + posSaida + "]");
                }
            }
        }

        if (!paresIndependentes.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.MEDIA,
                    paresIndependentes.size() + " par(es) sem dependência detectável em "
                            + this.perturbacoesPorPar + " tentativas cada",
                    Map.of("pares", paresIndependentes.subList(0, Math.min(20, paresIndependentes.size()))));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "Todos os " + (tamanho * tamanho) + " pares (entrada, saída) mostraram dependência");
    }
}

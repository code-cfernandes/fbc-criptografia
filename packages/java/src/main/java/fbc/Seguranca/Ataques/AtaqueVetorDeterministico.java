package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico.
 * De brinde, imprime o "vetor de referência" (Known Answer Vector) pra esse par
 * key/iv.
 */
public class AtaqueVetorDeterministico implements AtaqueInterface {
    @Override
    public String nome() {
        return "Determinismo (vetor de referência key/iv fixos)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        String chaveFixa = "K".repeat(alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length);
        byte[] ivFixo = new byte[alvo.tamanhoIv()];

        byte[] ks1 = alvo.gerarKeystreamBruto(
                chaveFixa.getBytes(StandardCharsets.UTF_8), ivFixo, "enc", 32);
        if (ks1 == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }
        byte[] ks2 = alvo.gerarKeystreamBruto(
                chaveFixa.getBytes(StandardCharsets.UTF_8), ivFixo, "enc", 32);
        byte[] ks3 = alvo.gerarKeystreamBruto(
                chaveFixa.getBytes(StandardCharsets.UTF_8), ivFixo, "enc", 32);

        boolean deterministico = Arrays.equals(ks1, ks2) && Arrays.equals(ks2, ks3);
        String hex = Util.bytesParaHex(ks1);

        return new ResultadoAtaque(
                nome(),
                !deterministico,
                deterministico ? Severidade.INFO : Severidade.CRITICA,
                deterministico
                        ? "Determinístico em 3 chamadas. Vetor de referência (key=64x\"K\", iv=zeros, prop=enc, 32 bytes): "
                                + hex
                        : "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: "
                                + hex + " / " + Util.bytesParaHex(ks2) + " / " + Util.bytesParaHex(ks3));
    }
}

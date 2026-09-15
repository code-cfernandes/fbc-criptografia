package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
 * um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
 *
 * Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
 * soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
 * a saída como função do byte variado fica "quase bijetiva" e a soma tende a
 * zero MUITO mais que o acaso - um distinguisher clássico.
 *
 * Como uma única (chave, IV) tem variância alta, acumula várias tentativas
 * para estimar o viés de forma estável (comparado a p=1/256).
 */
public class AtaqueIntegral implements AtaqueInterface {
    private final int tamanhoBloco;
    private final int posicoesIv;
    private final int posicoesChave;
    private final int tentativas;
    private final double limiteZ;

    public AtaqueIntegral() {
        this(32, 8, 8, 16, 5.0);
    }

    public AtaqueIntegral(
            int tamanhoBloco, int posicoesIv, int posicoesChave, int tentativas, double limiteZ) {
        this.tamanhoBloco = tamanhoBloco;
        this.posicoesIv = posicoesIv;
        this.posicoesChave = posicoesChave;
        this.tentativas = tentativas;
        this.limiteZ = limiteZ;
    }

    @Override
    public String nome() {
        return "Integral (soma balanceada variando 1 byte de IV/chave)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        int tamIv = alvo.tamanhoIv();
        int tamChave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8).length;

        byte[] primeiro = alvo.gerarKeystreamBruto(
                alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8),
                Util.randomBytes(tamIv),
                "enc",
                this.tamanhoBloco);
        if (primeiro == null) {
            throw new SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.");
        }

        List<String> distinguidores = new ArrayList<>();
        long zerosTotal = 0;
        long bytesTotal = 0;

        for (int t = 0; t < this.tentativas; t++) {
            byte[] chave = Util.randomBytes(tamChave);
            byte[] ivBase = Util.randomBytes(tamIv);

            for (int pos = 0; pos < Math.min(this.posicoesIv, tamIv); pos++) {
                long[] res = this.somarVariando(alvo, chave, ivBase, "iv", pos);
                zerosTotal += res[0];
                bytesTotal += this.tamanhoBloco;
                if (res[1] == 1) {
                    distinguidores.add("iv[" + pos + "]");
                }
            }

            for (int pos = 0; pos < Math.min(this.posicoesChave, tamChave); pos++) {
                long[] res = this.somarVariando(alvo, chave, ivBase, "key", pos);
                zerosTotal += res[0];
                bytesTotal += this.tamanhoBloco;
                if (res[1] == 1) {
                    distinguidores.add("key[" + pos + "]");
                }
            }
        }

        double p = 1.0 / 256;
        double esperado = bytesTotal * p;
        double desvio = Math.sqrt(bytesTotal * p * (1 - p));
        double z = desvio > 0 ? (zerosTotal - esperado) / desvio : 0.0;

        boolean vulneravel = !distinguidores.isEmpty() || z > this.limiteZ;

        if (!distinguidores.isEmpty()) {
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.CRITICA,
                    "Soma balanceada (XOR zero) encontrada variando: "
                            + String.join(", ", distinguidores.subList(0, Math.min(10, distinguidores.size()))),
                    Map.of("distinguidores", distinguidores));
        }

        Map<String, Object> dados = new HashMap<>();
        dados.put("zeros", zerosTotal);
        dados.put("esperado", esperado);
        dados.put("z", z);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.MEDIA : Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "bytes de saída zerados=%d (esperado ~%.1f, z=%.2f) em %d amostras; limite z=%.1f",
                        zerosTotal,
                        esperado,
                        z,
                        bytesTotal,
                        this.limiteZ),
                dados);
    }

    /** @return [quantidade de bytes zerados, 1 se todos os bytes são zero, senão 0] */
    private long[] somarVariando(
            AlvoCriptografico alvo, byte[] chave, byte[] ivBase, String campo, int pos) {
        byte[] xor = new byte[this.tamanhoBloco];
        for (int v = 0; v < 256; v++) {
            byte[] k = chave.clone();
            byte[] iv = ivBase.clone();
            if (campo.equals("iv")) {
                iv[pos] = (byte) v;
            } else {
                k[pos] = (byte) v;
            }
            byte[] ks = alvo.gerarKeystreamBruto(k, iv, "enc", this.tamanhoBloco);
            xor = this.xorBytes(xor, ks);
        }

        long zeros = 0;
        boolean todosZeros = true;
        for (byte b : xor) {
            if (b == 0) {
                zeros++;
            } else {
                todosZeros = false;
            }
        }
        return new long[] {zeros, todosZeros ? 1 : 0};
    }

    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        }
        return out;
    }
}

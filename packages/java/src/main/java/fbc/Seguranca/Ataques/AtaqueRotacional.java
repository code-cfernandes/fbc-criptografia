package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.Util;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
 * de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
 * `keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
 * byte e também coincidência direta do keystream.
 */
public class AtaqueRotacional implements AtaqueInterface {
    private final int tamanho;

    public AtaqueRotacional() {
        this(64);
    }

    public AtaqueRotacional(int tamanho) {
        this.tamanho = tamanho;
    }

    @Override
    public String nome() {
        return "Rotacional/slide (simetria por rotação)";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        byte[] chave = alvo.chaveDeTeste().getBytes(StandardCharsets.UTF_8);
        byte[] iv = Util.randomBytes(alvo.tamanhoIv());
        byte[] ks1 = alvo.gerarKeystreamBruto(chave, iv, "enc", this.tamanho);

        List<String> coincidencias = new ArrayList<>();
        for (int k = 1; k < chave.length; k++) {
            byte[] ks2 = alvo.gerarKeystreamBruto(
                    this.rotacionar(chave, k), this.rotacionar(iv, k), "enc", this.tamanho);

            if (Arrays.equals(ks2, ks1)) {
                coincidencias.add("rotação " + k + ": keystream idêntico");
                continue;
            }
            // metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
            byte[] alvoRot = this.rotacionar(Arrays.copyOfRange(ks1, 0, 32), k);
            if (Arrays.equals(Arrays.copyOfRange(ks2, 0, 32), alvoRot)) {
                coincidencias.add("rotação " + k + ": keystream rotacionado");
            }
        }

        boolean vulneravel = !coincidencias.isEmpty();

        Map<String, Object> dados = new HashMap<>();
        dados.put("coincidencias", coincidencias);

        return new ResultadoAtaque(
                nome(),
                vulneravel,
                vulneravel ? Severidade.CRITICA : Severidade.INFO,
                vulneravel
                        ? "Simetria rotacional encontrada: "
                                + String.join("; ", coincidencias.subList(0, Math.min(5, coincidencias.size())))
                        : "Nenhuma das " + (chave.length - 1)
                                + " rotações de byte reproduziu o keystream",
                dados);
    }

    private byte[] rotacionar(byte[] buf, int k) {
        int n = buf.length;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = buf[(i + k) % n];
        }
        return out;
    }
}

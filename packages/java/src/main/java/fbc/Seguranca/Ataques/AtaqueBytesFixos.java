package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * As primeiras versões dessa cifra tinham um header fixo ou um marcador
 * constante. Esse ataque gera vários tokens de textos diferentes e procura
 * qualquer posição de byte que NUNCA muda.
 */
public class AtaqueBytesFixos implements AtaqueInterface {
    private final int amostras;

    public AtaqueBytesFixos() {
        this(30);
    }

    public AtaqueBytesFixos(int amostras) {
        this.amostras = amostras;
    }

    @Override
    public String nome() {
        return "Bytes fixos entre tokens";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        List<byte[]> decodificados = new ArrayList<>();
        for (int i = 0; i < this.amostras; i++) {
            String texto = "TEXTO_VARIADO_" + i
                    + String.valueOf((char) ('A' + (i % 26))).repeat(i % 10);
            String token = alvo.encrypt(texto);
            decodificados.add(alvo.base64urlDecode(token.substring(alvo.prefixo().length())));
        }

        int tamanhoMinimo = Integer.MAX_VALUE;
        for (byte[] d : decodificados) {
            tamanhoMinimo = Math.min(tamanhoMinimo, d.length);
        }

        List<Integer> posicoesFixas = new ArrayList<>();
        for (int i = 0; i < tamanhoMinimo; i++) {
            Set<Integer> valores = new HashSet<>();
            for (byte[] d : decodificados) {
                valores.add(d[i] & 0xFF);
            }
            if (valores.size() == 1) {
                posicoesFixas.add(i);
            }
        }

        if (!posicoesFixas.isEmpty()) {
            List<String> primeiras = new ArrayList<>();
            for (int i = 0; i < Math.min(10, posicoesFixas.size()); i++) {
                primeiras.add(String.valueOf(posicoesFixas.get(i)));
            }
            return new ResultadoAtaque(
                    nome(),
                    true,
                    Severidade.ALTA,
                    posicoesFixas.size() + " posição(ões) de byte fixas em " + this.amostras
                            + " tokens: " + String.join(", ", primeiras));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                "0 de " + tamanhoMinimo + " posições fixas em " + this.amostras + " tokens");
    }
}

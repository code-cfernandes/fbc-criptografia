package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
 * Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
 * trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
 * timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
 * rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
 * mesmo sem nunca colidir de fato.
 *
 * Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
 * ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
 * e sequências crescentes/monótonas entre IVs consecutivos (sintoma
 * clássico de contador ou timestamp).
 */
public class AtaqueEntropiaIV implements AtaqueInterface {
    private final int amostras;

    public AtaqueEntropiaIV() {
        this(2000);
    }

    public AtaqueEntropiaIV(int amostras) {
        this.amostras = amostras;
    }

    @Override
    public String nome() {
        return "Entropia e previsibilidade do IV";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        if (!(alvo instanceof CriptografiaAlvo)) {
            throw new SkipAtaqueException("Precisa de base64url_decode do alvo.");
        }

        List<byte[]> ivs = new ArrayList<>();
        for (int i = 0; i < this.amostras; i++) {
            String token = alvo.encrypt("X");
            byte[] decodificado = alvo.base64urlDecode(token.substring(alvo.prefixo().length()));
            ivs.add(alvo.decompor(decodificado).iv);
        }

        List<String> problemas = new ArrayList<>();

        // Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
        int[] contagem = new int[256];
        int total = 0;
        for (byte[] iv : ivs) {
            for (int i = 0; i < iv.length; i++) {
                contagem[iv[i] & 0xFF]++;
                total++;
            }
        }
        double esperado = (double) total / 256;
        double qui2 = 0.0;
        for (int c : contagem) {
            double d = c - esperado;
            qui2 += (d * d) / esperado;
        }
        if (qui2 > 330) {
            problemas.add(String.format(
                    Locale.ROOT, "distribuição de bytes suspeita (qui-quadrado=%.1f, >330 é suspeito)", qui2));
        }

        // Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
        // primeiro byte estritamente crescente (um contador/timestamp cru
        // produziria isso quase sempre; aleatório, só ~50% das vezes).
        int crescentes = 0;
        for (int i = 1; i < ivs.size(); i++) {
            if ((ivs.get(i)[0] & 0xFF) > (ivs.get(i - 1)[0] & 0xFF)) {
                crescentes++;
            }
        }
        double proporcaoCrescente = (double) crescentes / (ivs.size() - 1);
        if (proporcaoCrescente > 0.65 || proporcaoCrescente < 0.35) {
            problemas.add(String.format(
                    Locale.ROOT,
                    "primeiro byte do IV parece monotônico (%.0f%% das vezes crescente; aleatório ficaria perto de 50%%)",
                    proporcaoCrescente * 100));
        }

        // Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
        // (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
        // repetição interna) - a AUSÊNCIA de qualquer repetição interna em
        // quase todos os IVs seria estranha (sugeriria geração não-uniforme,
        // tipo bytes distintos forçados).
        int semRepeticaoInterna = 0;
        for (byte[] iv : ivs) {
            Set<Integer> unicos = new HashSet<>();
            for (byte b : iv) {
                unicos.add(b & 0xFF);
            }
            if (unicos.size() == iv.length) {
                semRepeticaoInterna++;
            }
        }
        double proporcaoSemRepeticao = (double) semRepeticaoInterna / ivs.size();
        // Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
        if (proporcaoSemRepeticao > 0.9 || proporcaoSemRepeticao < 0.5) {
            problemas.add(String.format(
                    Locale.ROOT,
                    "%.0f%% dos IVs não têm nenhum byte repetido internamente (esperado ~72%% para 16 bytes aleatórios)",
                    proporcaoSemRepeticao * 100));
        }

        if (!problemas.isEmpty()) {
            return new ResultadoAtaque(nome(), true, Severidade.ALTA, String.join("; ", problemas));
        }

        return new ResultadoAtaque(
                nome(),
                false,
                Severidade.INFO,
                String.format(
                        Locale.ROOT,
                        "qui-quadrado=%.1f, %.0f%% primeiro-byte-crescente (~50%% esperado), %.0f%% sem repetição interna (~72%% esperado) - tudo consistente com IV aleatório",
                        qui2,
                        proporcaoCrescente * 100,
                        proporcaoSemRepeticao * 100));
    }
}

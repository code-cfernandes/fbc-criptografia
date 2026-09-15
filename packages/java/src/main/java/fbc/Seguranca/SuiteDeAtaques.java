package fbc.Seguranca;

import java.util.ArrayList;
import java.util.List;

public class SuiteDeAtaques {
    private final List<AtaqueInterface> ataques = new ArrayList<>();

    public SuiteDeAtaques adicionar(AtaqueInterface ataque) {
        this.ataques.add(ataque);
        return this;
    }

    public List<ResultadoAtaque> rodar(AlvoCriptografico alvo) {
        List<ResultadoAtaque> resultados = new ArrayList<>();
        for (AtaqueInterface ataque : this.ataques) {
            try {
                resultados.add(ataque.executar(alvo));
            } catch (SkipAtaqueException e) {
                resultados.add(new ResultadoAtaque(
                        ataque.nome(), false, Severidade.PULADO, "Pulado: " + e.getMessage()));
            } catch (Exception e) {
                String mensagem = e.getMessage() != null ? e.getMessage() : e.toString();
                resultados.add(new ResultadoAtaque(
                        ataque.nome(), true, Severidade.ERRO, "Erro ao executar: " + mensagem));
            }
        }
        return resultados;
    }

    /** Roda e imprime um relatório direto no console. Retorna true se não houver vulnerabilidade. */
    public boolean rodarEImprimir(AlvoCriptografico alvo) {
        List<ResultadoAtaque> resultados = this.rodar(alvo);
        int vulnerabilidades = 0;

        System.out.println("=".repeat(70));
        System.out.println("RELATÓRIO DA SUÍTE DE ATAQUES");
        System.out.println("=".repeat(70));
        System.out.println();

        for (ResultadoAtaque r : resultados) {
            System.out.println(r.linhaResumo());
            if (r.vulneravel() && r.severidade() != Severidade.PULADO
                    && r.severidade() != Severidade.DEMONSTRACAO) {
                vulnerabilidades++;
            }
        }

        System.out.println();
        System.out.println("=".repeat(70));
        if (vulnerabilidades == 0) {
            System.out.println("RESUMO: nenhuma vulnerabilidade encontrada em " + resultados.size()
                    + " ataque(s).");
        } else {
            System.out.println("RESUMO: " + vulnerabilidades + " vulnerabilidade(s) encontrada(s) de "
                    + resultados.size() + " ataque(s) rodados!");
        }
        System.out.println("=".repeat(70));

        return vulnerabilidades == 0;
    }
}

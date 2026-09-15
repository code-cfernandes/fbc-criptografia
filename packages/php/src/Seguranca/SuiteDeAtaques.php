<?php

namespace Application\Seguranca;

class SuiteDeAtaques
{
    /** @var AtaqueInterface[] */
    private array $ataques = [];

    public function adicionar(AtaqueInterface $ataque): static
    {
        $this->ataques[] = $ataque;
        return $this;
    }

    /** @return ResultadoAtaque[] */
    public function rodar(AlvoCriptografico $alvo): array
    {
        $resultados = [];
        foreach ($this->ataques as $ataque) {
            try {
                $resultados[] = $ataque->executar($alvo);
            } catch (SkipAtaqueException $e) {
                $resultados[] = new ResultadoAtaque(
                    $ataque->nome(),
                    vulneravel: false,
                    severidade: 'pulado',
                    detalhes: 'Pulado: ' . $e->getMessage(),
                );
            } catch (\Throwable $e) {
                $resultados[] = new ResultadoAtaque(
                    $ataque->nome(),
                    vulneravel: true,
                    severidade: 'erro',
                    detalhes: 'Erro ao executar: ' . $e->getMessage(),
                );
            }
        }
        return $resultados;
    }

    /** Roda e imprime um relatório direto no console. */
    public function rodarEImprimir(AlvoCriptografico $alvo): bool
    {
        $resultados = $this->rodar($alvo);
        $vulnerabilidades = 0;

        echo str_repeat('=', 70) . "\n";
        echo "RELATÓRIO DA SUÍTE DE ATAQUES\n";
        echo str_repeat('=', 70) . "\n\n";

        foreach ($resultados as $r) {
            echo $r->linhaResumo() . "\n";
            if ($r->vulneravel && !in_array($r->severidade, ['pulado', 'demonstracao'], true)) {
                $vulnerabilidades++;
            }
        }

        echo "\n" . str_repeat('=', 70) . "\n";
        if ($vulnerabilidades === 0) {
            echo "RESUMO: nenhuma vulnerabilidade encontrada em " . count($resultados) . " ataque(s).\n";
        } else {
            echo "RESUMO: $vulnerabilidades vulnerabilidade(s) encontrada(s) de " . count($resultados) . " ataque(s) rodados!\n";
        }
        echo str_repeat('=', 70) . "\n";

        return $vulnerabilidades === 0;
    }
}

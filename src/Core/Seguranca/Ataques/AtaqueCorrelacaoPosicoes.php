<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
 * correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
 * posições de saída é exatamente o tipo de estrutura que o antigo bug da
 * "metade igual" produzia - e que a autocorrelação temporal pode não pegar.
 */
class AtaqueCorrelacaoPosicoes implements AtaqueInterface
{
    public function __construct(
        private int $amostras = 3000,
        private int $tamanhoBloco = 32,
        private float $limiteCorrelacao = 0.15,
    ) {
    }

    public function nome(): string
    {
        return 'Correlação entre posições do bloco';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $blocos = [];
        for ($i = 0; $i < $this->amostras; $i++) {
            $blocos[] = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        }

        $suspeitos = [];
        $pior = 0.0;

        for ($a = 0; $a < $this->tamanhoBloco; $a++) {
            for ($b = $a + 1; $b < $this->tamanhoBloco; $b++) {
                $corr = $this->pearson($blocos, $a, $b);
                if (abs($corr) > abs($pior)) {
                    $pior = $corr;
                }
                if (abs($corr) > $this->limiteCorrelacao) {
                    $suspeitos[] = sprintf('posições %d-%d (r=%.3f)', $a, $b, $corr);
                }
            }
        }

        if (!empty($suspeitos)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'alta',
                detalhes: count($suspeitos) . ' par(es) correlacionado(s): ' . implode('; ', array_slice($suspeitos, 0, 10)),
                dados: ['suspeitos' => $suspeitos],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: sprintf('Nenhum par de posições correlacionado acima de %.2f (pior |r|=%.3f)', $this->limiteCorrelacao, abs($pior)),
        );
    }

    private function pearson(array $blocos, int $a, int $b): float
    {
        $n = count($blocos);
        $ma = 0.0;
        $mb = 0.0;
        foreach ($blocos as $d) {
            $ma += ord($d[$a]);
            $mb += ord($d[$b]);
        }
        $ma /= $n;
        $mb /= $n;

        $num = 0.0;
        $da = 0.0;
        $db = 0.0;
        foreach ($blocos as $d) {
            $xa = ord($d[$a]) - $ma;
            $xb = ord($d[$b]) - $mb;
            $num += $xa * $xb;
            $da += $xa * $xa;
            $db += $xb * $xb;
        }

        return ($da > 0 && $db > 0) ? $num / sqrt($da * $db) : 0.0;
    }
}

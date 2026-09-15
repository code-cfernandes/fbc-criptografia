<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
 * passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
 * pequeno que o monobit quase não vê faz o desvio acumulado crescer.
 * Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
 */
class AtaqueCusum implements AtaqueInterface
{
    public function __construct(private int $tamanho = 8192, private float $limiteZ = 4.0)
    {
    }

    public function nome(): string
    {
        return 'Somas cumulativas (cusum)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $ks = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
        if ($ks === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $soma = 0;
        $maxAbs = 0;
        for ($i = 0; $i < strlen($ks); $i++) {
            $byte = ord($ks[$i]);
            for ($b = 7; $b >= 0; $b--) {
                $soma += (($byte >> $b) & 1) === 1 ? 1 : -1;
                $maxAbs = max($maxAbs, abs($soma));
            }
        }
        $n = strlen($ks) * 8;
        $z = $maxAbs / sqrt($n);
        $vulneravel = $z > $this->limiteZ;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: sprintf('max|S|=%d sobre %d bits, max|S|/sqrt(n)=%.2f (limite=%.1f)', $maxAbs, $n, $z, $this->limiteZ),
            dados: ['max_abs' => $maxAbs, 'z' => $z],
        );
    }
}

<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
 * gerado (efeito avalanche). Números muito abaixo disso indicam difusão
 * fraca - foi o que achamos quando o número de rodadas de mistura era
 * baixo demais numa das versões anteriores.
 */
class AtaqueAvalanche implements AtaqueInterface
{
    public function __construct(
        private int $amostras = 3000,
        private int $tamanhoBloco = 32,
        private float $limiteMedia = 0.45,
        private float $limitePiorCaso = 0.30,
    ) {
    }

    public function nome(): string
    {
        return 'Efeito avalanche';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $tamanhoIv = $alvo->tamanhoIv();

        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($tamanhoIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $valores = [];
        for ($t = 0; $t < $this->amostras; $t++) {
            $iv1 = random_bytes($tamanhoIv);
            $iv2 = $iv1;
            $pos = random_int(0, $tamanhoIv - 1);
            $iv2[$pos] = chr(ord($iv2[$pos]) ^ (1 << random_int(0, 7)));

            $ks1 = $alvo->gerarKeystreamBruto($chave, $iv1, 'enc', $this->tamanhoBloco);
            $ks2 = $alvo->gerarKeystreamBruto($chave, $iv2, 'enc', $this->tamanhoBloco);

            $valores[] = $this->bitsDiferentes($ks1, $ks2) / ($this->tamanhoBloco * 8);
        }

        sort($valores);
        $n = count($valores);
        $media = array_sum($valores) / $n;
        $piorCaso = $valores[0];

        $vulneravel = $media < $this->limiteMedia || $piorCaso < $this->limitePiorCaso;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'média=%.1f%%, pior caso=%.1f%%, percentil 1%%=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)',
                $media * 100,
                $piorCaso * 100,
                $valores[(int) ($n * 0.01)] * 100,
                $this->limiteMedia * 100,
                $this->limitePiorCaso * 100,
            ),
            dados: ['media' => $media, 'pior_caso' => $piorCaso],
        );
    }

    private function bitsDiferentes(string $a, string $b): int
    {
        $diff = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $diff += substr_count(decbin(ord($a[$i]) ^ ord($b[$i])), '1');
        }
        return $diff;
    }
}

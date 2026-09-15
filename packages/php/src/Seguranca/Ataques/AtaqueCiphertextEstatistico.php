<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
 * (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
 * de cifra sólida deve parecer ruído mesmo com plaintext variado.
 */
class AtaqueCiphertextEstatistico implements AtaqueInterface
{
    public function __construct(
        private int $amostras = 200,
        private int $tamanhoTexto = 64,
        private float $zLimite = 4,
    ) {
    }

    public function nome(): string
    {
        return 'Estatística do ciphertext (chi²/runs/autocorrelação)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $contagem = array_fill(0, 256, 0);
        $bytes = [];

        for ($s = 0; $s < $this->amostras; $s++) {
            $texto = random_bytes($this->tamanhoTexto);
            $token = $alvo->encrypt($texto);
            $campos = $alvo->decompor($alvo->base64urlDecode(substr($token, strlen($alvo->prefixo()))));

            $ct = $campos['ciphertext'];
            $lenCt = strlen($ct);
            for ($i = 0; $i < $lenCt; $i++) {
                $b = ord($ct[$i]);
                $contagem[$b]++;
                $bytes[] = $b;
            }
        }

        $total = count($bytes);
        $esperado = $total / 256;
        $chi2 = 0.0;
        for ($b = 0; $b < 256; $b++) {
            $d = $contagem[$b] - $esperado;
            $chi2 += ($d * $d) / $esperado;
        }

        // runs test nos bits do ciphertext
        $uns = 0;
        $bits = [];
        for ($i = 0; $i < $total; $i++) {
            $b = $bytes[$i];
            for ($k = 7; $k >= 0; $k--) {
                $bit = ($b >> $k) & 1;
                $bits[] = $bit;
                $uns += $bit;
            }
        }
        $n = count($bits);
        $pi = $uns / $n;
        $runs = 1;
        for ($i = 1; $i < $n; $i++) {
            if ($bits[$i] !== $bits[$i - 1]) {
                $runs++;
            }
        }
        $esperadoRuns = 2 * $n * $pi * (1 - $pi);
        $desvioRuns = 2 * sqrt(2 * $n) * $pi * (1 - $pi);
        $zRuns = $desvioRuns > 0 ? abs($runs - $esperadoRuns) / $desvioRuns : 0.0;

        // autocorrelação lag-1
        $media = array_sum($bytes) / $total;
        $num = 0.0;
        $den = 0.0;
        for ($i = 0; $i < $total; $i++) {
            $den += ($bytes[$i] - $media) ** 2;
        }
        for ($i = 0; $i < $total - 1; $i++) {
            $num += ($bytes[$i] - $media) * ($bytes[$i + 1] - $media);
        }
        $autocorr = $den > 0 ? $num / $den : 0.0;

        $problemas = [];
        if ($chi2 > 330) {
            $problemas[] = sprintf('qui-quadrado=%.1f (>330 suspeito)', $chi2);
        }
        if ($zRuns > $this->zLimite) {
            $problemas[] = sprintf('runs z=%.2f', $zRuns);
        }
        if (abs($autocorr) > 0.1) {
            $problemas[] = sprintf('autocorrelação=%.3f', $autocorr);
        }

        $vulneravel = !empty($problemas);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: $vulneravel
                ? implode('; ', $problemas)
                : sprintf(
                    'qui-quadrado=%.1f sobre %d bytes, runs z=%.2f, autocorrelação=%.3f - todos dentro do esperado',
                    $chi2,
                    $total,
                    $zRuns,
                    $autocorr,
                ),
            dados: ['chi2' => $chi2, 'runs_z' => $zRuns, 'autocorrelacao' => $autocorr],
        );
    }
}

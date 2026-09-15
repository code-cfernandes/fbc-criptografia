<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
 * global (monobit), frequência por posição de bit, teste de runs e frequência
 * por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
 * e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
 *
 * Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
 * pra não depender de funções numéricas especiais.
 */
class AtaqueBateriaEstatistica implements AtaqueInterface
{
    public function __construct(private int $tamanho = 16384, private float $zLimite = 4.0)
    {
    }

    public function nome(): string
    {
        return 'Bateria estatística de bits (monobit/runs/blocos)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $ks = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
        if ($ks === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $bits = $this->paraBits($ks);
        $n = count($bits);
        $problemas = [];
        $dados = [];

        // 1) Monobit: soma +1/-1
        $soma = 0;
        foreach ($bits as $b) {
            $soma += $b === 1 ? 1 : -1;
        }
        $zMonobit = abs($soma) / sqrt($n);
        $dados['monobit_z'] = $zMonobit;
        if ($zMonobit > $this->zLimite) {
            $problemas[] = sprintf('monobit z=%.2f', $zMonobit);
        }

        // 2) Frequência por posição de bit
        $unsPorPos = array_fill(0, 8, 0);
        $contaPorPos = array_fill(0, 8, 0);
        foreach (str_split($ks) as $c) {
            $byte = ord($c);
            for ($b = 0; $b < 8; $b++) {
                if ((($byte >> $b) & 1) === 1) {
                    $unsPorPos[$b]++;
                }
                $contaPorPos[$b]++;
            }
        }
        $posViesadas = [];
        foreach ($unsPorPos as $b => $uns) {
            $frac = $uns / $contaPorPos[$b];
            $z = abs($frac - 0.5) / (0.5 / sqrt($contaPorPos[$b]));
            if ($z > $this->zLimite) {
                $posViesadas[$b] = $frac;
            }
        }
        $dados['bit_posicao_viesadas'] = $posViesadas;
        if (!empty($posViesadas)) {
            $problemas[] = 'viés por posição de bit: ' . implode(', ', array_keys($posViesadas));
        }

        // 3) Runs test
        $pi = array_sum($bits) / $n;
        if (abs($pi - 0.5) < 2 / sqrt($n)) {
            $runs = 1;
            for ($i = 1; $i < $n; $i++) {
                if ($bits[$i] !== $bits[$i - 1]) {
                    $runs++;
                }
            }
            $esperado = 2 * $n * $pi * (1 - $pi);
            $desvio = 2 * sqrt(2 * $n) * $pi * (1 - $pi);
            $zRuns = abs($runs - $esperado) / $desvio;
            $dados['runs_z'] = $zRuns;
            if ($zRuns > $this->zLimite) {
                $problemas[] = sprintf('runs z=%.2f', $zRuns);
            }
        }

        // 4) Frequência por bloco (M = 128 bits)
        $m = 128;
        $numBlocos = intdiv($n, $m);
        if ($numBlocos > 0) {
            $chi = 0.0;
            for ($i = 0; $i < $numBlocos; $i++) {
                $uns = 0;
                for ($j = 0; $j < $m; $j++) {
                    $uns += $bits[$i * $m + $j];
                }
                $chi += (($uns / $m) - 0.5) ** 2;
            }
            $chi *= 4 * $m;
            $zBlocos = ($chi - $numBlocos) / sqrt(2 * $numBlocos);
            $dados['blocos_chi2'] = $chi;
            $dados['blocos_z'] = $zBlocos;
            if ($zBlocos > $this->zLimite) {
                $problemas[] = sprintf('frequência por bloco chi2=%.1f', $chi);
            }
        }

        if (!empty($problemas)) {
            return new ResultadoAtaque($this->nome(), true, 'media', implode('; ', $problemas), $dados);
        }

        return new ResultadoAtaque(
            $this->nome(),
            false,
            'info',
            sprintf(
                'monobit z=%.2f, runs z=%.2f, blocos chi2=%.1f - todos abaixo do limite z=%.0f',
                $zMonobit,
                $dados['runs_z'] ?? 0.0,
                $dados['blocos_chi2'] ?? 0.0,
                $this->zLimite,
            ),
            $dados,
        );
    }

    /** @return list<int> */
    private function paraBits(string $bytes): array
    {
        $bits = [];
        for ($i = 0; $i < strlen($bytes); $i++) {
            $byte = ord($bytes[$i]);
            for ($b = 7; $b >= 0; $b--) {
                $bits[] = ($byte >> $b) & 1;
            }
        }
        return $bits;
    }
}

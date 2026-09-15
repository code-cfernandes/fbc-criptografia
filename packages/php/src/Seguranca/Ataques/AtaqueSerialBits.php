<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
 * gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
 * locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
 * aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
 */
class AtaqueSerialBits implements AtaqueInterface
{
    public function __construct(private int $tamanho = 4096, private array $ordens = [2, 3, 4])
    {
    }

    public function nome(): string
    {
        return 'Teste serial (padrões de bits sobrepostos)';
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

        foreach ($this->ordens as $m) {
            $total = 1 << $m;
            $contagem = array_fill(0, $total, 0);
            $janelas = $n - $m + 1;

            for ($i = 0; $i < $janelas; $i++) {
                $v = 0;
                for ($j = 0; $j < $m; $j++) {
                    $v = ($v << 1) | $bits[$i + $j];
                }
                $contagem[$v]++;
            }

            $esperado = $janelas / $total;
            $chi2 = 0.0;
            foreach ($contagem as $c) {
                $chi2 += (($c - $esperado) ** 2) / $esperado;
            }
            $dof = $total - 1;
            // Wilson-Hilferty: aproximação normal bem mais precisa para dof
            // pequeno (o z "ingênuo" dá ~5% de falso positivo em dof=3).
            $z = (($chi2 / $dof) ** (1 / 3) - (1 - 2 / (9 * $dof))) / sqrt(2 / (9 * $dof));
            $dados["m$m"] = ['chi2' => $chi2, 'z' => $z];

            if ($z > 6.0) {
                $problemas[] = sprintf('m=%d chi2=%.1f (z=%.1f)', $m, $chi2, $z);
            }
        }

        if (!empty($problemas)) {
            return new ResultadoAtaque($this->nome(), true, 'media', implode('; ', $problemas), $dados);
        }

        return new ResultadoAtaque(
            $this->nome(),
            false,
            'info',
            'Padrões sobrepostos de 2/3/4 bits com frequência uniforme',
            $dados,
        );
    }

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

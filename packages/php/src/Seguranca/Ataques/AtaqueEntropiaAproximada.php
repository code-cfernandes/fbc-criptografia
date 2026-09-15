<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
 * previsibilidade local: para uma sequência aleatória, a chance de repetir um
 * bloco de m bits deve cair suavemente conforme m cresce. Estruturas
 * periódicas/recorrentes produzem ApEn anômala.
 *
 * O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
 * um valor esperado teórico. Comparamos o keystream com um CONTROLE de
 * random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
 * estatisticamente indistinguíveis.
 */
class AtaqueEntropiaAproximada implements AtaqueInterface
{
    public function __construct(
        private int $tamanho = 4096,
        private int $m = 8,
        private int $controles = 12,
        private int $amostrasKeystream = 3,
        private float $limiteZ = 5.0,
    ) {
    }

    public function nome(): string
    {
        return 'Entropia aproximada (ApEn vs controle aleatório)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $primeiro = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', 64);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $chiControle = [];
        for ($c = 0; $c < $this->controles; $c++) {
            $chiControle[] = $this->estatistico(random_bytes($this->tamanho));
        }
        $mediaControle = array_sum($chiControle) / count($chiControle);
        $variancia = 0.0;
        foreach ($chiControle as $v) {
            $variancia += ($v - $mediaControle) ** 2;
        }
        $desvioControle = sqrt($variancia / max(1, count($chiControle) - 1));

        $chiKeystream = [];
        for ($k = 0; $k < $this->amostrasKeystream; $k++) {
            $ks = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
            $chiKeystream[] = $this->estatistico($ks);
        }
        $mediaKeystream = array_sum($chiKeystream) / count($chiKeystream);

        $z = $desvioControle > 0 ? ($mediaKeystream - $mediaControle) / $desvioControle : 0.0;
        $vulneravel = abs($z) > $this->limiteZ;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: sprintf(
                'chi2 keystream=%.1f, controle=%.1f (sd=%.1f), z=%.2f (limite=%.1f)',
                $mediaKeystream,
                $mediaControle,
                $desvioControle,
                $z,
                $this->limiteZ,
            ),
            dados: ['chi_keystream' => $mediaKeystream, 'chi_controle' => $mediaControle, 'z' => $z],
        );
    }

    /** chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1). */
    private function estatistico(string $bytes): float
    {
        $bits = $this->paraBits($bytes);
        $n = count($bits);
        $apen = $this->phi($bits, $this->m, $n) - $this->phi($bits, $this->m + 1, $n);
        return 2 * $n * (log(2) - $apen);
    }

    /** @param list<int> $bits */
    private function phi(array $bits, int $m, int $n): float
    {
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

        $soma = 0.0;
        foreach ($contagem as $c) {
            if ($c > 0) {
                $p = $c / $janelas;
                $soma += $p * log($p);
            }
        }

        return $soma;
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

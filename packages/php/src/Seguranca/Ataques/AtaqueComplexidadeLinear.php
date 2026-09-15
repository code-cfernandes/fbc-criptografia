<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
 * reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
 * complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
 * um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
 * seria atacável resolvendo um sistema linear em vez de força bruta.
 */
class AtaqueComplexidadeLinear implements AtaqueInterface
{
    public function __construct(
        private int $bitsPorAmostra = 1024,
        private int $amostras = 5,
        private float $limiteRelativo = 0.40,
    ) {
    }

    public function nome(): string
    {
        return 'Complexidade linear (Berlekamp-Massey)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', 64);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $relativos = [];
        $pior = 1.0;
        for ($a = 0; $a < $this->amostras; $a++) {
            $bytes = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', intdiv($this->bitsPorAmostra, 8));
            $bits = $this->paraBits($bytes, $this->bitsPorAmostra);
            $relativo = $this->berlekampMassey($bits) / $this->bitsPorAmostra;
            $relativos[] = $relativo;
            $pior = min($pior, $relativo);
        }

        $media = array_sum($relativos) / count($relativos);
        $vulneravel = $pior < $this->limiteRelativo;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: sprintf(
                'complexidade linear relativa: média=%.1f%%, pior=%.1f%% de %d bits (esperado ~50%%; limite>=%.0f%%)',
                $media * 100,
                $pior * 100,
                $this->bitsPorAmostra,
                $this->limiteRelativo * 100,
            ),
            dados: ['media' => $media, 'pior' => $pior],
        );
    }

    /** @return list<int> */
    private function paraBits(string $bytes, int $limite): array
    {
        $bits = [];
        for ($i = 0; $i < strlen($bytes) && count($bits) < $limite; $i++) {
            $byte = ord($bytes[$i]);
            for ($b = 7; $b >= 0; $b--) {
                $bits[] = ($byte >> $b) & 1;
            }
        }
        return array_slice($bits, 0, $limite);
    }

    /**
     * Algoritmo de Berlekamp-Massey sobre GF(2).
     *
     * @param list<int> $s
     */
    private function berlekampMassey(array $s): int
    {
        $n = count($s);
        $c = array_fill(0, $n, 0);
        $c[0] = 1;
        $b = array_fill(0, $n, 0);
        $b[0] = 1;
        $l = 0;
        $m = -1;

        for ($i = 0; $i < $n; $i++) {
            $d = $s[$i];
            for ($j = 1; $j <= $l; $j++) {
                $d ^= $c[$j] & $s[$i - $j];
            }

            if ($d === 1) {
                $t = $c;
                $shift = $i - $m;
                for ($j = 0; $j + $shift < $n; $j++) {
                    $c[$j + $shift] ^= $b[$j];
                }
                if ($l <= intdiv($i, 2)) {
                    $l = $i + 1 - $l;
                    $m = $i;
                    $b = $t;
                }
            }
        }

        return $l;
    }
}

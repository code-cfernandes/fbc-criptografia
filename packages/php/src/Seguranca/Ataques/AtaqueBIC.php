<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * BIC (Bit Independence Criterion): pares de bits de saída não devem estar
 * correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
 * e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
 * cada par de bits de saída. Pares muito correlacionados indicam difusão
 * acoplada (um bit "carrega" informação sobre outro).
 */
class AtaqueBIC implements AtaqueInterface
{
    public function __construct(
        private int $tamanhoBloco = 32,
        private int $amostras = 300,
        private float $limite = 0.35,
    ) {
    }

    public function nome(): string
    {
        return 'BIC (Bit Independence Criterion)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $totalBits = $this->tamanhoBloco * 8;
        $tamanhoIv = $alvo->tamanhoIv();

        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($tamanhoIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $amostrasFlips = [];
        for ($s = 0; $s < $this->amostras; $s++) {
            $iv1 = random_bytes($tamanhoIv);
            $iv2 = $iv1;
            $pos = random_int(0, $tamanhoIv - 1);
            $iv2[$pos] = chr(ord($iv2[$pos]) ^ (1 << random_int(0, 7)));

            $ks1 = $alvo->gerarKeystreamBruto($chave, $iv1, 'enc', $this->tamanhoBloco);
            $ks2 = $alvo->gerarKeystreamBruto($chave, $iv2, 'enc', $this->tamanhoBloco);

            $flips = [];
            for ($j = 0; $j < $totalBits; $j++) {
                $b1 = (ord($ks1[$j >> 3]) >> (7 - ($j & 7))) & 1;
                $b2 = (ord($ks2[$j >> 3]) >> (7 - ($j & 7))) & 1;
                $flips[$j] = $b1 !== $b2 ? 1 : 0;
            }
            $amostrasFlips[] = $flips;
        }

        $piorPhi = 0.0;
        $piorPar = [-1, -1];
        $n = $this->amostras;

        for ($a = 0; $a < $totalBits; $a++) {
            for ($b = $a + 1; $b < $totalBits; $b++) {
                $n11 = 0;
                $n10 = 0;
                $n01 = 0;
                $n00 = 0;
                for ($s = 0; $s < $n; $s++) {
                    $fa = $amostrasFlips[$s][$a];
                    $fb = $amostrasFlips[$s][$b];
                    if ($fa === 1 && $fb === 1) {
                        $n11++;
                    } elseif ($fa === 1 && $fb === 0) {
                        $n10++;
                    } elseif ($fa === 0 && $fb === 1) {
                        $n01++;
                    } else {
                        $n00++;
                    }
                }
                $den = sqrt(($n11 + $n10) * ($n01 + $n00) * ($n11 + $n01) * ($n10 + $n00));
                $phi = $den > 0 ? ($n11 * $n00 - $n10 * $n01) / $den : 0.0;
                if (abs($phi) > abs($piorPhi)) {
                    $piorPhi = $phi;
                    $piorPar = [$a, $b];
                }
            }
        }

        $vulneravel = abs($piorPhi) > $this->limite;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'maior |phi|=%.3f entre bits de saída [%d, %d] (limite %s); %d amostras',
                abs($piorPhi),
                $piorPar[0],
                $piorPar[1],
                $this->limite,
                $n,
            ),
            dados: ['pior_phi' => $piorPhi, 'par' => $piorPar],
        );
    }
}

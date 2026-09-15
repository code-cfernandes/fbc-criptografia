<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
 * esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
 * bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
 */
class AtaqueSAC implements AtaqueInterface
{
    public function __construct(
        private int $tamanhoBloco = 32,
        private int $amostras = 40,
        private float $tolerancia = 0.05,
    ) {
    }

    public function nome(): string
    {
        return 'SAC (Strict Avalanche Criterion)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $totalBits = $this->tamanhoBloco * 8;
        $flips = array_fill(0, $totalBits, 0);
        $tamanhoIv = $alvo->tamanhoIv();
        $total = 0;

        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($tamanhoIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        for ($pos = 0; $pos < $tamanhoIv; $pos++) {
            for ($bit = 0; $bit < 8; $bit++) {
                for ($s = 0; $s < $this->amostras; $s++) {
                    $iv1 = random_bytes($tamanhoIv);
                    $iv2 = $iv1;
                    $iv2[$pos] = chr(ord($iv2[$pos]) ^ (1 << $bit));

                    $ks1 = $alvo->gerarKeystreamBruto($chave, $iv1, 'enc', $this->tamanhoBloco);
                    $ks2 = $alvo->gerarKeystreamBruto($chave, $iv2, 'enc', $this->tamanhoBloco);

                    for ($j = 0; $j < $totalBits; $j++) {
                        $b1 = (ord($ks1[$j >> 3]) >> (7 - ($j & 7))) & 1;
                        $b2 = (ord($ks2[$j >> 3]) >> (7 - ($j & 7))) & 1;
                        if ($b1 !== $b2) {
                            $flips[$j]++;
                        }
                    }
                    $total++;
                }
            }
        }

        $pior = -1;
        $piorDesvio = 0.0;
        $piorP = 0.5;
        for ($j = 0; $j < $totalBits; $j++) {
            $p = $flips[$j] / $total;
            $desvio = abs($p - 0.5);
            if ($desvio > $piorDesvio) {
                $piorDesvio = $desvio;
                $pior = $j;
                $piorP = $p;
            }
        }

        $vulneravel = $piorDesvio > $this->tolerancia;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'pior bit de saída=%d: p=%.2f%% (esperado 50%%, tolerância ±%.1f%%); %d amostras por bit de entrada',
                $pior,
                $piorP * 100,
                $this->tolerancia * 100,
                $total,
            ),
            dados: ['pior' => $pior, 'pior_p' => $piorP, 'desvio' => $piorDesvio],
        );
    }
}

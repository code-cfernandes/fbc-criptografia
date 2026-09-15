<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Aproximação linear (criptoanálise de Matsui): procura por correlação entre
 * bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
 * aproximação linear com viés relevante; bias alto é uma pista explorável.
 */
class AtaqueAproximacaoLinear implements AtaqueInterface
{
    public function __construct(
        private int $amostras = 200,
        private int $tamanhoBloco = 32,
        private float $limiteBias = 0.3,
    ) {
    }

    public function nome(): string
    {
        return 'Aproximação linear (viés de Walsh)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tamIv = $alvo->tamanhoIv();
        $bitsEntrada = $tamIv * 8;
        $bitsSaida = $this->tamanhoBloco * 8;
        $tamChave = strlen($alvo->chaveDeTeste());

        $primeiro = $alvo->gerarKeystreamBruto(random_bytes($tamChave), random_bytes($tamIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $entradas = [];
        $saidas = [];

        for ($s = 0; $s < $this->amostras; $s++) {
            $chave = random_bytes($tamChave);
            $iv = random_bytes($tamIv);
            $ks = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanhoBloco);

            $inBits = [];
            for ($j = 0; $j < $bitsEntrada; $j++) {
                $inBits[$j] = (ord($iv[$j >> 3]) >> (7 - ($j & 7))) & 1;
            }
            $outBits = [];
            for ($j = 0; $j < $bitsSaida; $j++) {
                $outBits[$j] = (ord($ks[$j >> 3]) >> (7 - ($j & 7))) & 1;
            }
            $entradas[] = $inBits;
            $saidas[] = $outBits;
        }

        $maiorBias = 0.0;
        $par = [-1, -1];
        for ($i = 0; $i < $bitsEntrada; $i++) {
            for ($j = 0; $j < $bitsSaida; $j++) {
                $iguais = 0;
                for ($s = 0; $s < $this->amostras; $s++) {
                    if ($entradas[$s][$i] === $saidas[$s][$j]) {
                        $iguais++;
                    }
                }
                $bias = abs($iguais / $this->amostras - 0.5);
                if ($bias > $maiorBias) {
                    $maiorBias = $bias;
                    $par = [$i, $j];
                }
            }
        }

        $vulneravel = $maiorBias > $this->limiteBias;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'maior viés |p-0.5|=%.4f na aproximação IV[bit %d] -> saída[bit %d] (limite %s); %d amostras',
                $maiorBias,
                $par[0],
                $par[1],
                $this->limiteBias,
                $this->amostras,
            ),
            dados: ['maior_bias' => $maiorBias, 'par' => $par],
        );
    }
}

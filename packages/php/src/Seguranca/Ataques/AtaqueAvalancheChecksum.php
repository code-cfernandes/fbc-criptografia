<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
 * interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
 * dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
 * posição específica significa que aquele byte quase não influencia o MAC -
 * uma pista forte de que a mistura tem um "ponto cego" estrutural.
 *
 * Varre TODAS as posições/bits da entrada (não amostra aleatória) para
 * apontar exatamente onde está o ponto fraco.
 */
class AtaqueAvalancheChecksum implements AtaqueInterface
{
    public function __construct(
        private int $mensagensPorCombinacao = 10,
        private int $tamanhoEntrada = 32,
        private float $limiteMedia = 0.40,
        private float $limitePiorCaso = 0.40,
    ) {
    }

    public function nome(): string
    {
        return 'Efeito avalanche do checksum/MAC';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveMac = str_repeat('M', 32);

        $primeiro = $alvo->checksumBruto('teste', $chaveMac);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
        }
        $tamanhoSaida = strlen($primeiro);

        $somaGlobal = 0.0;
        $combinacoes = 0;
        $pior = ['posicao' => -1, 'bit' => -1, 'valor' => 1.0];

        for ($pos = 0; $pos < $this->tamanhoEntrada; $pos++) {
            for ($bit = 0; $bit < 8; $bit++) {
                $soma = 0.0;
                for ($m = 0; $m < $this->mensagensPorCombinacao; $m++) {
                    $entrada = random_bytes($this->tamanhoEntrada);
                    $alterada = $entrada;
                    $alterada[$pos] = chr(ord($alterada[$pos]) ^ (1 << $bit));

                    $h1 = $alvo->checksumBruto($entrada, $chaveMac);
                    $h2 = $alvo->checksumBruto($alterada, $chaveMac);

                    $soma += $this->bitsDiferentes($h1, $h2) / ($tamanhoSaida * 8);
                }
                $media = $soma / $this->mensagensPorCombinacao;

                $somaGlobal += $media;
                $combinacoes++;
                if ($media < $pior['valor']) {
                    $pior = ['posicao' => $pos, 'bit' => $bit, 'valor' => $media];
                }
            }
        }

        $mediaGlobal = $somaGlobal / $combinacoes;
        $vulneravel = $mediaGlobal < $this->limiteMedia || $pior['valor'] < $this->limitePiorCaso;

        if (!$vulneravel) {
            $severidade = 'info';
        } elseif ($pior['valor'] < 0.30) {
            $severidade = 'alta';
        } else {
            $severidade = 'media';
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $severidade,
            detalhes: sprintf(
                'média global=%.1f%%; pior caso=%.1f%% na entrada[posição=%d, bit=%d] sobre %d bytes de MAC (limites: média>=%.0f%%, pior>=%.0f%%)',
                $mediaGlobal * 100,
                $pior['valor'] * 100,
                $pior['posicao'],
                $pior['bit'],
                $tamanhoSaida,
                $this->limiteMedia * 100,
                $this->limitePiorCaso * 100,
            ),
            dados: ['media_global' => $mediaGlobal, 'pior' => $pior],
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

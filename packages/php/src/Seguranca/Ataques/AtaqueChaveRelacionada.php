<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
 * 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
 * schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
 * estrutura (distância de Hamming baixa).
 */
class AtaqueChaveRelacionada implements AtaqueInterface
{
    public function __construct(
        private int $tamanhoBloco = 32,
        private int $ivPorDelta = 3,
        private float $limiteMedia = 0.45,
        private float $limitePior = 0.3,
    ) {
    }

    public function nome(): string
    {
        return 'Chave relacionada (related-key)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveBase = $alvo->chaveDeTeste();
        $len = strlen($chaveBase);

        $primeiro = $alvo->gerarKeystreamBruto($chaveBase, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $deltas = [];
        for ($i = 0; $i < $len; $i++) {
            $d = str_repeat("\x00", $len);
            $d[$i] = "\x01";
            $deltas[] = $d;
        }
        for ($i = 0; $i < $len; $i++) {
            $d = str_repeat("\x00", $len);
            $d[$i] = "\xFF";
            $deltas[] = $d;
        }
        $complemento = '';
        for ($i = 0; $i < $len; $i++) {
            $complemento .= chr(ord($chaveBase[$i]) ^ 0xFF);
        }
        $deltas[] = $complemento;

        $valores = [];
        $totalBits = $this->tamanhoBloco * 8;

        foreach ($deltas as $delta) {
            $chaveRelacionada = $chaveBase;
            for ($i = 0; $i < $len; $i++) {
                $chaveRelacionada[$i] = chr(ord($chaveRelacionada[$i]) ^ ord($delta[$i]));
            }
            for ($s = 0; $s < $this->ivPorDelta; $s++) {
                $iv = random_bytes($alvo->tamanhoIv());
                $ks1 = $alvo->gerarKeystreamBruto($chaveBase, $iv, 'enc', $this->tamanhoBloco);
                $ks2 = $alvo->gerarKeystreamBruto($chaveRelacionada, $iv, 'enc', $this->tamanhoBloco);
                $valores[] = $this->bitsDiferentes($ks1, $ks2) / $totalBits;
            }
        }

        $media = array_sum($valores) / count($valores);
        $pior = min($valores);
        $vulneravel = $media < $this->limiteMedia || $pior < $this->limitePior;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'média=%.1f%%, pior=%.1f%% em %d pares (limites: média>=%.0f%%, pior>=%.0f%%)',
                $media * 100,
                $pior * 100,
                count($valores),
                $this->limiteMedia * 100,
                $this->limitePior * 100,
            ),
            dados: ['media' => $media, 'pior' => $pior],
        );
    }

    private function bitsDiferentes(string $a, string $b): int
    {
        $diff = 0;
        $len = min(strlen($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $diff += substr_count(decbin(ord($a[$i]) ^ ord($b[$i])), '1');
        }
        return $diff;
    }
}

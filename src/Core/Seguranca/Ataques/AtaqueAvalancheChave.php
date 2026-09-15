<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
 * CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
 * inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
 * Números baixos indicam que parte da chave tem pouca influência - o que
 * reduziria o espaço de busca de um atacante.
 */
class AtaqueAvalancheChave implements AtaqueInterface
{
    public function __construct(
        private int $amostras = 3000,
        private int $tamanhoBloco = 32,
        private float $limiteMedia = 0.45,
        private float $limitePiorCaso = 0.30,
    ) {
    }

    public function nome(): string
    {
        return 'Efeito avalanche da chave';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveBase = $alvo->chaveDeTeste();
        $lenChave = strlen($chaveBase);
        $iv = random_bytes($alvo->tamanhoIv());

        $primeiro = $alvo->gerarKeystreamBruto($chaveBase, $iv, 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $valores = [];
        for ($t = 0; $t < $this->amostras; $t++) {
            $chave = $chaveBase;
            $pos = random_int(0, $lenChave - 1);
            $chave[$pos] = chr(ord($chave[$pos]) ^ (1 << random_int(0, 7)));

            $ks1 = $alvo->gerarKeystreamBruto($chaveBase, $iv, 'enc', $this->tamanhoBloco);
            $ks2 = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanhoBloco);

            $valores[] = $this->bitsDiferentes($ks1, $ks2) / ($this->tamanhoBloco * 8);
        }

        sort($valores);
        $n = count($valores);
        $media = array_sum($valores) / $n;
        $piorCaso = $valores[0];

        $vulneravel = $media < $this->limiteMedia || $piorCaso < $this->limitePiorCaso;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'média=%.1f%%, pior caso=%.1f%% (limites: média>=%.0f%%, pior>=%.0f%%)',
                $media * 100,
                $piorCaso * 100,
                $this->limiteMedia * 100,
                $this->limitePiorCaso * 100,
            ),
            dados: ['media' => $media, 'pior_caso' => $piorCaso],
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

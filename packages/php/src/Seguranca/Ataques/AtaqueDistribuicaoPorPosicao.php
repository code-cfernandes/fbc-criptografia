<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
 * bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
 * soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
 */
class AtaqueDistribuicaoPorPosicao implements AtaqueInterface
{
    public function __construct(private int $amostrasDeBlocos = 2000, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Distribuição de bytes por posição do bloco';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $contagens = [];
        for ($p = 0; $p < $this->tamanhoBloco; $p++) {
            $contagens[$p] = array_fill(0, 256, 0);
        }

        for ($i = 0; $i < $this->amostrasDeBlocos; $i++) {
            $ks = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
            for ($p = 0; $p < $this->tamanhoBloco; $p++) {
                $contagens[$p][ord($ks[$p])]++;
            }
        }

        $esperado = $this->amostrasDeBlocos / 256;
        $problemas = [];
        $pior = 0.0;

        foreach ($contagens as $p => $c) {
            $chi2 = 0.0;
            foreach ($c as $v) {
                $chi2 += (($v - $esperado) ** 2) / $esperado;
            }
            $pior = max($pior, $chi2);
            $z = ($chi2 - 255) / sqrt(510);
            if ($z > 4.0) {
                $problemas[] = sprintf('posição %d chi2=%.1f', $p, $chi2);
            }
        }

        if (!empty($problemas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'media',
                detalhes: implode('; ', $problemas),
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: sprintf('Todas as %d posições uniformes (pior chi2=%.1f, esperado ~255)', $this->tamanhoBloco, $pior),
        );
    }
}

<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
 * 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
 * de byte saem com mais frequência que outros - sinal de fraqueza estatística
 * na função de mistura.
 */
class AtaqueDistribuicaoBytes implements AtaqueInterface
{
    public function __construct(private int $amostrasDeBlocos = 500, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Distribuição de bytes (qui-quadrado)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $contagem = array_fill(0, 256, 0);
        $total = 0;
        for ($i = 0; $i < $this->amostrasDeBlocos; $i++) {
            $ks = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
            for ($j = 0; $j < strlen($ks); $j++) {
                $contagem[ord($ks[$j])]++;
                $total++;
            }
        }

        $esperado = $total / 256;
        $qui2 = 0.0;
        foreach ($contagem as $c) {
            $qui2 += (($c - $esperado) ** 2) / $esperado;
        }

        // Com 255 graus de liberdade, valores acima de ~330 já são
        // estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
        $vulneravel = $qui2 > 330;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: sprintf('qui-quadrado=%.1f sobre %d bytes (255 graus de liberdade; >330 é suspeito)', $qui2, $total),
            dados: ['qui2' => $qui2],
        );
    }
}

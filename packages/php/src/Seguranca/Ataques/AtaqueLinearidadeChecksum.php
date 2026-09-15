<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Procura linearidade no checksum, que seria fatal para um MAC:
 *  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
 *  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
 *     cada a; se repetir muito, existe um diferencial de alta probabilidade
 *     que ajuda a forjar MACs.
 */
class AtaqueLinearidadeChecksum implements AtaqueInterface
{
    public function __construct(
        private int $amostrasLinearidade = 5000,
        private int $amostrasDiferencial = 500,
        private int $tamanhoEntrada = 32,
    ) {
    }

    public function nome(): string
    {
        return 'Linearidade e diferenciais do checksum';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveMac = str_repeat('M', 32);
        $primeiro = $alvo->checksumBruto('teste', $chaveMac);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
        }

        $relacoesLineares = 0;
        for ($i = 0; $i < $this->amostrasLinearidade; $i++) {
            $a = random_bytes($this->tamanhoEntrada);
            $b = random_bytes($this->tamanhoEntrada);
            $lhs = $this->xorBytes($alvo->checksumBruto($a, $chaveMac), $alvo->checksumBruto($b, $chaveMac));
            $rhs = $alvo->checksumBruto($this->xorBytes($a, $b), $chaveMac);
            if ($lhs === $rhs) {
                $relacoesLineares++;
            }
        }

        $maxRepeticoesDiferencial = 0;
        for ($d = 0; $d < 5; $d++) {
            $delta = random_bytes($this->tamanhoEntrada);
            $vistos = [];
            for ($i = 0; $i < $this->amostrasDiferencial; $i++) {
                $a = random_bytes($this->tamanhoEntrada);
                $dif = $this->xorBytes($alvo->checksumBruto($this->xorBytes($a, $delta), $chaveMac), $alvo->checksumBruto($a, $chaveMac));
                $vistos[$dif] = ($vistos[$dif] ?? 0) + 1;
            }
            $maxRepeticoesDiferencial = max($maxRepeticoesDiferencial, max($vistos));
        }

        $vulneravel = $relacoesLineares > 0 || $maxRepeticoesDiferencial > 1;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: sprintf(
                '%d/%d relações lineares; maior repetição de diferencial=%d (esperado 1)',
                $relacoesLineares,
                $this->amostrasLinearidade,
                $maxRepeticoesDiferencial,
            ),
            dados: ['relacoes_lineares' => $relacoesLineares, 'max_repeticoes_diferencial' => $maxRepeticoesDiferencial],
        );
    }

    private function xorBytes(string $a, string $b): string
    {
        $out = '';
        $len = min(strlen($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $out;
    }
}

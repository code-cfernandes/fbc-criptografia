<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
 * IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
 * boa, essas diferenças são uniformes e únicas. Sinaliza:
 *  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
 *  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
 *    que é o insumo básico de um ataque diferencial.
 */
class AtaqueDiferencialKeystream implements AtaqueInterface
{
    public function __construct(private int $amostras = 2000, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Diferencial do keystream (delta fixo no IV)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = random_bytes(strlen($alvo->chaveDeTeste()));
        $tamanhoIv = $alvo->tamanhoIv();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($tamanhoIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $delta = str_repeat("\x00", $tamanhoIv);
        $delta[random_int(0, $tamanhoIv - 1)] = chr(1 << random_int(0, 7));

        $totalBits = $this->tamanhoBloco * 8;
        $sempreZero = array_fill(0, $totalBits, true);
        $sempreUm = array_fill(0, $totalBits, true);
        $deltas = [];

        for ($i = 0; $i < $this->amostras; $i++) {
            $iv = random_bytes($tamanhoIv);
            $iv2 = $this->xorBytes($iv, $delta);

            $ks1 = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanhoBloco);
            $ks2 = $alvo->gerarKeystreamBruto($chave, $iv2, 'enc', $this->tamanhoBloco);
            $d = $this->xorBytes($ks1, $ks2);
            $deltas[$d] = true;

            for ($p = 0; $p < strlen($d); $p++) {
                $byte = ord($d[$p]);
                for ($b = 0; $b < 8; $b++) {
                    $idx = $p * 8 + $b;
                    if ((($byte >> $b) & 1) === 1) {
                        $sempreZero[$idx] = false;
                    } else {
                        $sempreUm[$idx] = false;
                    }
                }
            }
        }

        $bitsFixos = 0;
        for ($idx = 0; $idx < $totalBits; $idx++) {
            if ($sempreZero[$idx] || $sempreUm[$idx]) {
                $bitsFixos++;
            }
        }
        $colisoes = $this->amostras - count($deltas);

        $vulneravel = $bitsFixos > 0 || $colisoes > 0;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'delta de 1 bit no IV: %d bit(s) de saída fixo(s), %d diferencial(is) repetido(s) em %d amostras',
                $bitsFixos,
                $colisoes,
                $this->amostras,
            ),
            dados: ['bits_fixos' => $bitsFixos, 'colisoes' => $colisoes],
        );
    }

    private function xorBytes(string $a, string $b): string
    {
        $out = '';
        for ($i = 0; $i < strlen($a); $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $out;
    }
}

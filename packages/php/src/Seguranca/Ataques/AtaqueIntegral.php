<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
 * um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
 *
 * Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
 * soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
 * a saída como função do byte variado fica "quase bijetiva" e a soma tende a
 * zero MUITO mais que o acaso - um distinguisher clássico.
 *
 * Como uma única (chave, IV) tem variância alta, acumula várias tentativas
 * para estimar o viés de forma estável (comparado a p=1/256).
 */
class AtaqueIntegral implements AtaqueInterface
{
    public function __construct(
        private int $tamanhoBloco = 32,
        private int $posicoesIv = 8,
        private int $posicoesChave = 8,
        private int $tentativas = 16,
        private float $limiteZ = 5.0,
    ) {
    }

    public function nome(): string
    {
        return 'Integral (soma balanceada variando 1 byte de IV/chave)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tamIv = $alvo->tamanhoIv();
        $tamChave = strlen($alvo->chaveDeTeste());

        $primeiro = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($tamIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $distinguidores = [];
        $zerosTotal = 0;
        $bytesTotal = 0;

        for ($t = 0; $t < $this->tentativas; $t++) {
            $chave = random_bytes($tamChave);
            $ivBase = random_bytes($tamIv);

            for ($pos = 0; $pos < min($this->posicoesIv, $tamIv); $pos++) {
                [$xor, $zeros] = $this->somarVariando($alvo, $chave, $ivBase, 'iv', $pos);
                $zerosTotal += $zeros;
                $bytesTotal += $this->tamanhoBloco;
                if ($xor === str_repeat("\x00", $this->tamanhoBloco)) {
                    $distinguidores[] = "iv[$pos]";
                }
            }

            for ($pos = 0; $pos < min($this->posicoesChave, $tamChave); $pos++) {
                [$xor, $zeros] = $this->somarVariando($alvo, $chave, $ivBase, 'key', $pos);
                $zerosTotal += $zeros;
                $bytesTotal += $this->tamanhoBloco;
                if ($xor === str_repeat("\x00", $this->tamanhoBloco)) {
                    $distinguidores[] = "key[$pos]";
                }
            }
        }

        $p = 1 / 256;
        $esperado = $bytesTotal * $p;
        $desvio = sqrt($bytesTotal * $p * (1 - $p));
        $z = $desvio > 0 ? ($zerosTotal - $esperado) / $desvio : 0.0;

        $vulneravel = !empty($distinguidores) || $z > $this->limiteZ;

        if (!empty($distinguidores)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: 'Soma balanceada (XOR zero) encontrada variando: ' . implode(', ', array_slice($distinguidores, 0, 10)),
                dados: ['distinguidores' => $distinguidores],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: sprintf(
                'bytes de saída zerados=%d (esperado ~%.1f, z=%.2f) em %d amostras; limite z=%.1f',
                $zerosTotal,
                $esperado,
                $z,
                $bytesTotal,
                $this->limiteZ,
            ),
            dados: ['zeros' => $zerosTotal, 'esperado' => $esperado, 'z' => $z],
        );
    }

    /** @return array{0: string, 1: int} XOR de 256 keystreams e quantos bytes deram zero */
    private function somarVariando(AlvoCriptografico $alvo, string $chave, string $ivBase, string $campo, int $pos): array
    {
        $xor = str_repeat("\x00", $this->tamanhoBloco);
        for ($v = 0; $v < 256; $v++) {
            $k = $chave;
            $iv = $ivBase;
            if ($campo === 'iv') {
                $iv[$pos] = chr($v);
            } else {
                $k[$pos] = chr($v);
            }
            $ks = $alvo->gerarKeystreamBruto($k, $iv, 'enc', $this->tamanhoBloco);
            $xor = $this->xorBytes($xor, $ks);
        }
        return [$xor, substr_count($xor, "\x00")];
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

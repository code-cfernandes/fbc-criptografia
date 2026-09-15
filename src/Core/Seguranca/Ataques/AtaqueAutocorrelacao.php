<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
 * Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
 * autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
 * estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
 * keystream aleatório deve ter todos esses indicadores perto de zero/50%.
 */
class AtaqueAutocorrelacao implements AtaqueInterface
{
    public function __construct(private int $tamanho = 8192, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Autocorrelação e periodicidade do keystream';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $ks = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
        if ($ks === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $serial = $this->correlacao($ks, 1);

        $suspeitos = [];
        foreach ([2, 4, 8, 16, 32, 64, 128, 256] as $lag) {
            $c = $this->correlacao($ks, $lag);
            if (abs($c) > 0.10) {
                $suspeitos[$lag] = $c;
            }
        }

        $blocos = str_split($ks, $this->tamanhoBloco);
        $blocosRepetidos = count($blocos) - count(array_unique($blocos));

        $uns = 0;
        for ($i = 0; $i < strlen($ks); $i++) {
            $uns += substr_count(decbin(ord($ks[$i])), '1');
        }
        $fracaoUns = $uns / (strlen($ks) * 8);

        $problemas = [];
        if (abs($serial) > 0.10) {
            $problemas[] = sprintf('correlação serial=%.3f', $serial);
        }
        if (!empty($suspeitos)) {
            $problemas[] = 'autocorrelação em lag(s) ' . implode(', ', array_keys($suspeitos));
        }
        if ($blocosRepetidos > 0) {
            $problemas[] = "$blocosRepetidos bloco(s) de {$this->tamanhoBloco} bytes repetido(s)";
        }
        if ($fracaoUns < 0.45 || $fracaoUns > 0.55) {
            $problemas[] = sprintf('balanço de bits=%.1f%% de 1s', $fracaoUns * 100);
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
            detalhes: sprintf(
                'serial=%.3f, nenhum lag com correlação >10%%, 0 blocos repetidos em %d, %.1f%% de bits 1',
                $serial,
                count($blocos),
                $fracaoUns * 100,
            ),
        );
    }

    private function correlacao(string $s, int $lag): float
    {
        $n = strlen($s);
        if ($n <= $lag) {
            return 0.0;
        }

        $media = array_sum(array_map('ord', str_split($s))) / $n;
        $num = 0.0;
        $den = 0.0;
        for ($i = 0; $i < $n; $i++) {
            $den += (ord($s[$i]) - $media) ** 2;
        }
        for ($i = 0; $i < $n - $lag; $i++) {
            $num += (ord($s[$i]) - $media) * (ord($s[$i + $lag]) - $media);
        }

        return $den > 0 ? $num / $den : 0.0;
    }
}

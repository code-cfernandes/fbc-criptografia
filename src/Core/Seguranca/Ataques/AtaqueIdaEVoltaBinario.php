<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
 * verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
 * vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
 * truncation) só aparecem com bytes arbitrários.
 */
class AtaqueIdaEVoltaBinario implements AtaqueInterface
{
    public function __construct(private int $tamanhoMaximo = 256)
    {
    }

    public function nome(): string
    {
        return 'Ida-e-volta com dados binários (inclui NUL)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $falhas = [];

        for ($len = 0; $len <= $this->tamanhoMaximo; $len++) {
            $texto = $len === 0 ? '' : random_bytes($len);
            try {
                if ($alvo->decrypt($alvo->encrypt($texto)) !== $texto) {
                    $falhas[] = $len;
                }
            } catch (\Throwable $e) {
                $falhas[] = "$len (erro: {$e->getMessage()})";
            }
        }

        $todos = implode('', array_map('chr', range(0, 255)));
        if ($alvo->decrypt($alvo->encrypt($todos)) !== $todos) {
            $falhas[] = 'todos os 256 valores de byte';
        }

        if (!empty($falhas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: 'Falhou em ' . count($falhas) . ' caso(s): ' . implode(', ', array_slice($falhas, 0, 10)),
                dados: ['falhas' => $falhas],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Todos os tamanhos 0..{$this->tamanhoMaximo} e os 256 valores de byte preservados",
        );
    }
}

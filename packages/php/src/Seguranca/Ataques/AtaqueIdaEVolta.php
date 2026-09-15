<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;

/**
 * Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
 * de decrypt precisa devolver o texto original, em qualquer tamanho.
 * Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
 * segurança mais sério por trás (foi assim em quase todas as rodadas
 * anteriores dessa conversa).
 */
class AtaqueIdaEVolta implements AtaqueInterface
{
    public function __construct(private int $tamanhoMaximo = 130)
    {
    }

    public function nome(): string
    {
        return 'Ida-e-volta (round trip)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $falhas = [];
        for ($len = 0; $len <= $this->tamanhoMaximo; $len++) {
            $texto = str_repeat('Q', $len);
            try {
                $token = $alvo->encrypt($texto);
                $decifrado = $alvo->decrypt($token);
                if ($decifrado !== $texto) {
                    $falhas[] = $len;
                }
            } catch (\Throwable $e) {
                $falhas[] = "$len (erro: {$e->getMessage()})";
            }
        }

        if (!empty($falhas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: 'Falhou em ' . count($falhas) . ' tamanho(s): ' . implode(', ', array_slice($falhas, 0, 10)),
                dados: ['falhas' => $falhas],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Todos os " . ($this->tamanhoMaximo + 1) . " tamanhos (0 a {$this->tamanhoMaximo}) OK",
        );
    }
}

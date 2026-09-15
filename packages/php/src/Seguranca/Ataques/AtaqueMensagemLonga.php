<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;

/**
 * Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
 * sincronização de bloco, repetição de keystream em blocos distantes ou
 * perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
 * curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
 * gera tokens diferentes.
 */
class AtaqueMensagemLonga implements AtaqueInterface
{
    public function __construct(private array $tamanhos = [1000, 10000, 100000])
    {
    }

    public function nome(): string
    {
        return 'Mensagens longas (multi-bloco)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $falhas = [];

        foreach ($this->tamanhos as $t) {
            $texto = random_bytes($t);
            try {
                $token = $alvo->encrypt($texto);
                if ($alvo->decrypt($token) !== $texto) {
                    $falhas[] = "$t bytes (conteúdo diferente)";
                }
            } catch (\Throwable $e) {
                $falhas[] = "$t bytes (erro: {$e->getMessage()})";
            }
        }

        $texto = str_repeat('A', 1000);
        $t1 = $alvo->encrypt($texto);
        $t2 = $alvo->encrypt($texto);
        if ($t1 === $t2) {
            $falhas[] = 'tokens idênticos para o mesmo texto (IV não varia)';
        }

        if (!empty($falhas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: 'Falha em: ' . implode('; ', $falhas),
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Ida-e-volta OK em ' . implode(', ', $this->tamanhos) . ' bytes; mesmo texto gera tokens distintos',
        );
    }
}

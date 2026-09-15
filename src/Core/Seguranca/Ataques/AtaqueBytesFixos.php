<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * As primeiras versões dessa cifra tinham um header fixo (43 bytes idênticos
 * sempre) ou um marcador constante (o '$' na posição 64). Esse ataque gera
 * vários tokens de textos diferentes e procura qualquer posição de byte que
 * NUNCA muda - isso é uma âncora que um atacante pode usar pra recuperar a
 * chave (como fizemos na primeira rodada dessa conversa).
 */
class AtaqueBytesFixos implements AtaqueInterface
{
    public function __construct(private int $amostras = 30)
    {
    }

    public function nome(): string
    {
        return 'Bytes fixos entre tokens';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tokens = [];
        for ($i = 0; $i < $this->amostras; $i++) {
            $texto = 'TEXTO_VARIADO_' . $i . str_repeat(chr(65 + ($i % 26)), $i % 10);
            $tokens[] = substr($alvo->encrypt($texto), strlen($alvo->prefixo()));
        }

        $decodificados = array_map(fn($t) => base64_decode(strtr($t, '-_', '+/') . str_repeat('=', (4 - strlen($t) % 4) % 4)), $tokens);
        $tamanhoMinimo = min(array_map('strlen', $decodificados));

        $posicoesFixas = [];
        for ($i = 0; $i < $tamanhoMinimo; $i++) {
            $valores = array_map(fn($d) => $d[$i], $decodificados);
            if (count(array_unique($valores)) === 1) {
                $posicoesFixas[] = $i;
            }
        }

        if (!empty($posicoesFixas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'alta',
                detalhes: count($posicoesFixas) . " posição(ões) de byte fixas em {$this->amostras} tokens: " . implode(', ', array_slice($posicoesFixas, 0, 10)),
                dados: ['posicoes' => $posicoesFixas],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "0 de $tamanhoMinimo posições fixas em {$this->amostras} tokens",
        );
    }
}

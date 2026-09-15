<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
 * (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
 * produzir keystream degenerado - e aqui testamos no pior cenário, com IV
 * zerado junto, pra isolar a contribuição da chave.
 */
class AtaqueChavesDegeneradas implements AtaqueInterface
{
    public function __construct(private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tamChave = strlen($alvo->chaveDeTeste());
        $ivZero = str_repeat("\x00", $alvo->tamanhoIv());

        $primeiro = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), $ivZero, 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $casos = [
            'zero' => str_repeat("\x00", $tamChave),
            '0xFF' => str_repeat("\xFF", $tamChave),
            'alternada 0xAA' => str_repeat("\xAA", $tamChave),
            'alternada 0x55' => str_repeat("\x55", $tamChave),
            'repetida "A"' => str_repeat('A', $tamChave),
            'crescente' => substr(str_repeat(implode('', array_map('chr', range(0, 255))), 2), 0, $tamChave),
        ];

        $problemas = [];
        foreach ($casos as $nome => $chave) {
            $ks = $alvo->gerarKeystreamBruto($chave, $ivZero, 'enc', $this->tamanhoBloco);

            $metade = intdiv($this->tamanhoBloco, 2);
            $periodico = substr($ks, 0, $metade) === substr($ks, $metade, $metade);
            $bytesUnicos = count(array_unique(array_map('ord', str_split($ks))));

            if ($periodico || $bytesUnicos < $this->tamanhoBloco * 0.5) {
                $problemas[$nome] = ['periodico' => $periodico, 'bytes_unicos' => $bytesUnicos];
            }
        }

        if (!empty($problemas)) {
            $detalhe = implode('; ', array_map(
                fn($nome, $info) => "$nome (periódico=" . ($info['periodico'] ? 'sim' : 'não') . ", bytes únicos={$info['bytes_unicos']}/{$this->tamanhoBloco})",
                array_keys($problemas),
                $problemas
            ));
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'alta',
                detalhes: $detalhe,
                dados: $problemas,
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Nenhuma das ' . count($casos) . ' chaves degeneradas testadas produziu saída anômala',
        );
    }
}

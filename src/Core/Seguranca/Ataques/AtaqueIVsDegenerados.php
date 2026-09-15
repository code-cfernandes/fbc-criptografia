<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
 * (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
 * mesmo quando a maioria das entradas se comporta bem. Testa especificamente
 * esses casos extremos, que testes com entrada aleatória raramente cobrem.
 */
class AtaqueIVsDegenerados implements AtaqueInterface
{
    public function nome(): string
    {
        return 'IVs degenerados (zero, 0xFF, alternado)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $tamanhoIv = $alvo->tamanhoIv();
        $tamanhoBloco = 32;

        $primeiro = $alvo->gerarKeystreamBruto($chave, str_repeat("\x00", $tamanhoIv), 'enc', $tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $casos = [
            'zero' => str_repeat("\x00", $tamanhoIv),
            '0xFF' => str_repeat("\xFF", $tamanhoIv),
            'alternado 0xAA' => str_repeat("\xAA", $tamanhoIv),
            'alternado 0x55' => str_repeat("\x55", $tamanhoIv),
            'crescente' => implode('', array_map('chr', range(0, $tamanhoIv - 1))),
        ];

        $problemas = [];
        foreach ($casos as $nome => $iv) {
            $ks = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $tamanhoBloco);

            $metade = intdiv($tamanhoBloco, 2);
            $periodico = substr($ks, 0, $metade) === substr($ks, $metade, $metade);

            $bytesUnicos = count(array_unique(array_map('ord', str_split($ks))));
            $poucaVariedade = $bytesUnicos < $tamanhoBloco * 0.5;

            if ($periodico || $poucaVariedade) {
                $problemas[$nome] = compact('periodico', 'bytesUnicos');
            }
        }

        if (!empty($problemas)) {
            $detalhe = implode('; ', array_map(
                fn($nome, $info) => "$nome (periódico=" . ($info['periodico'] ? 'sim' : 'não') . ", bytes únicos={$info['bytesUnicos']}/$tamanhoBloco)",
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
            detalhes: 'Nenhum dos ' . count($casos) . ' IVs degenerados testados produziu saída anômala',
        );
    }
}

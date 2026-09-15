<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
 * produzir keystream anômalo (repetição, período curto, viés de bits ou
 * distribuição de bytes distorcida). Complementa o ataque de chaves
 * degeneradas, que só checa a saída do encrypt.
 */
class AtaqueChavesFracas implements AtaqueInterface
{
    public function __construct(
        private int $tamanho = 2048,
        private float $toleranciaBits = 0.05,
    ) {
    }

    public function nome(): string
    {
        return 'Chaves fracas (busca dirigida)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $len = strlen($alvo->chaveDeTeste());

        $casos = [
            ['nome' => 'zeros', 'chave' => str_repeat("\x00", $len)],
            ['nome' => '0xFF', 'chave' => str_repeat("\xFF", $len)],
            ['nome' => 'alternada AA/55', 'chave' => $this->alternada($len, 0xAA, 0x55)],
            ['nome' => 'incremental', 'chave' => $this->incremental($len)],
            ['nome' => 'um bit', 'chave' => chr(1) . str_repeat("\x00", $len - 1)],
            ['nome' => 'byte repetido 0x01', 'chave' => str_repeat("\x01", $len)],
            ['nome' => 'padrão AB', 'chave' => $this->alternada($len, 0x41, 0x42)],
        ];

        $ivFixo = str_repeat("\x00", $alvo->tamanhoIv());
        $anomalias = [];

        $primeiro = $alvo->gerarKeystreamBruto($casos[0]['chave'], $ivFixo, 'enc', $this->tamanho);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        foreach ($casos as $caso) {
            $ks = $alvo->gerarKeystreamBruto($caso['chave'], $ivFixo, 'enc', $this->tamanho);

            $blocos = [];
            $repetidos = 0;
            $tamKs = strlen($ks);
            for ($i = 0; $i + 32 <= $tamKs; $i += 32) {
                $hex = bin2hex(substr($ks, $i, 32));
                if (isset($blocos[$hex])) {
                    $repetidos++;
                } else {
                    $blocos[$hex] = true;
                }
            }

            $fracaoUns = $this->contarBits($ks) / ($tamKs * 8);
            $desvioBits = abs($fracaoUns - 0.5);

            if ($repetidos > 0) {
                $anomalias[] = "{$caso['nome']}: $repetidos bloco(s) repetido(s)";
            }
            if ($desvioBits > $this->toleranciaBits) {
                $anomalias[] = sprintf('%s: viés de bits %.1f%%', $caso['nome'], $fracaoUns * 100);
            }
        }

        $vulneravel = !empty($anomalias);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: $vulneravel
                ? 'Anomalias: ' . implode('; ', array_slice($anomalias, 0, 5))
                : 'Nenhuma das ' . count($casos) . " chaves fracas produziu keystream anômalo ({$this->tamanho} bytes cada)",
            dados: ['anomalias' => $anomalias],
        );
    }

    private function alternada(int $len, int $a, int $b): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr($i % 2 === 0 ? $a : $b);
        }
        return $out;
    }

    private function incremental(int $len): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr($i & 0xFF);
        }
        return $out;
    }

    private function contarBits(string $buf): int
    {
        $total = 0;
        $len = strlen($buf);
        for ($i = 0; $i < $len; $i++) {
            $total += substr_count(decbin(ord($buf[$i])), '1');
        }
        return $total;
    }
}

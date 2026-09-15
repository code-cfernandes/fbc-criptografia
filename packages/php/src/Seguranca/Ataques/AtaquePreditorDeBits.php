<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
 * primeira metade do keystream e mede a taxa de acerto na segunda metade.
 * Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
 * Qualquer coisa acima disso indica que os bits carregam dependência
 * explorável - o embrião de um ataque de predição de estado.
 */
class AtaquePreditorDeBits implements AtaqueInterface
{
    public function __construct(
        private int $tamanho = 16384,
        private int $contexto = 8,
        private float $limiteTaxa = 0.55,
    ) {
    }

    public function nome(): string
    {
        return 'Previsibilidade de bits (preditor por contexto)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $ks = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
        if ($ks === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $bits = $this->paraBits($ks);
        $n = count($bits);
        $k = $this->contexto;
        $total = 1 << $k;
        $metade = intdiv($n, 2);

        $uns = array_fill(0, $total, 0);
        $cont = array_fill(0, $total, 0);
        for ($i = $k; $i < $metade; $i++) {
            $ctx = $this->contexto($bits, $i, $k);
            $uns[$ctx] += $bits[$i];
            $cont[$ctx]++;
        }

        $acertos = 0;
        $testes = 0;
        for ($i = $metade; $i < $n; $i++) {
            $ctx = $this->contexto($bits, $i, $k);
            if ($cont[$ctx] === 0) {
                continue;
            }
            $predicao = ($uns[$ctx] * 2 > $cont[$ctx]) ? 1 : 0;
            if ($predicao === $bits[$i]) {
                $acertos++;
            }
            $testes++;
        }

        $taxa = $testes > 0 ? $acertos / $testes : 0.5;
        $vulneravel = $taxa > $this->limiteTaxa;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'taxa de acerto=%.2f%% com contexto de %d bits (esperado ~50%%, limite=%.0f%%) sobre %d testes',
                $taxa * 100,
                $k,
                $this->limiteTaxa * 100,
                $testes,
            ),
            dados: ['taxa' => $taxa, 'testes' => $testes],
        );
    }

    /** @param list<int> $bits */
    private function contexto(array $bits, int $i, int $k): int
    {
        $ctx = 0;
        for ($j = $i - $k; $j < $i; $j++) {
            $ctx = ($ctx << 1) | $bits[$j];
        }
        return $ctx;
    }

    /** @return list<int> */
    private function paraBits(string $bytes): array
    {
        $bits = [];
        for ($i = 0; $i < strlen($bytes); $i++) {
            $byte = ord($bytes[$i]);
            for ($b = 7; $b >= 0; $b--) {
                $bits[] = ($byte >> $b) & 1;
            }
        }
        return $bits;
    }
}

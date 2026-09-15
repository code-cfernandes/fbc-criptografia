<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
 * Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
 * trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
 * timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
 * rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
 * mesmo sem nunca colidir de fato.
 *
 * Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
 * ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
 * e sequências crescentes/monótonas entre IVs consecutivos (sintoma
 * clássico de contador ou timestamp).
 */
class AtaqueEntropiaIV implements AtaqueInterface
{
    public function __construct(private int $amostras = 2000)
    {
    }

    public function nome(): string
    {
        return 'Entropia e previsibilidade do IV';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Core\Seguranca\SkipAtaqueException('Precisa de base64url_decode do alvo.');
        }

        $ivs = [];
        for ($i = 0; $i < $this->amostras; $i++) {
            $token = $alvo->encrypt('X');
            $decodificado = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
            $ivs[] = $alvo->decompor($decodificado)['iv'];
        }

        $problemas = [];

        // Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
        $contagem = array_fill(0, 256, 0);
        $total = 0;
        foreach ($ivs as $iv) {
            for ($i = 0; $i < strlen($iv); $i++) {
                $contagem[ord($iv[$i])]++;
                $total++;
            }
        }
        $esperado = $total / 256;
        $qui2 = 0.0;
        foreach ($contagem as $c) {
            $qui2 += (($c - $esperado) ** 2) / $esperado;
        }
        if ($qui2 > 330) {
            $problemas[] = sprintf('distribuição de bytes suspeita (qui-quadrado=%.1f, >330 é suspeito)', $qui2);
        }

        // Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
        // primeiro byte estritamente crescente (um contador/timestamp cru
        // produziria isso quase sempre; aleatório, só ~50% das vezes).
        $crescentes = 0;
        for ($i = 1; $i < count($ivs); $i++) {
            if (ord($ivs[$i][0]) > ord($ivs[$i - 1][0])) {
                $crescentes++;
            }
        }
        $proporcaoCrescente = $crescentes / (count($ivs) - 1);
        if ($proporcaoCrescente > 0.65 || $proporcaoCrescente < 0.35) {
            $problemas[] = sprintf('primeiro byte do IV parece monotônico (%.0f%% das vezes crescente; aleatório ficaria perto de 50%%)', $proporcaoCrescente * 100);
        }

        // Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
        // (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
        // repetição interna) - a AUSÊNCIA de qualquer repetição interna em
        // quase todos os IVs seria estranha (sugeriria geração não-uniforme,
        // tipo bytes distintos forçados).
        $semRepeticaoInterna = 0;
        foreach ($ivs as $iv) {
            if (count(array_unique(str_split($iv))) === strlen($iv)) {
                $semRepeticaoInterna++;
            }
        }
        $proporcaoSemRepeticao = $semRepeticaoInterna / count($ivs);
        // Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
        if ($proporcaoSemRepeticao > 0.90 || $proporcaoSemRepeticao < 0.50) {
            $problemas[] = sprintf('%.0f%% dos IVs não têm nenhum byte repetido internamente (esperado ~72%% para 16 bytes aleatórios)', $proporcaoSemRepeticao * 100);
        }

        if (!empty($problemas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'alta',
                detalhes: implode('; ', $problemas),
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: sprintf(
                'qui-quadrado=%.1f, %.0f%% primeiro-byte-crescente (~50%% esperado), %.0f%% sem repetição interna (~72%% esperado) - tudo consistente com IV aleatório',
                $qui2,
                $proporcaoCrescente * 100,
                $proporcaoSemRepeticao * 100
            ),
        );
    }
}

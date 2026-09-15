<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;

/**
 * Se a comparação de integridade não for de tempo constante (ex: usar ===
 * em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
 * iniciais do campo de integridade batem, comparando o tempo de resposta -
 * e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
 *
 * Esse teste gera um token válido, cria versões adulteradas onde o campo
 * de integridade erra em posições DIFERENTES (início vs. fim do campo), e
 * compara o tempo médio de decrypt() entre os grupos. Uma diferença
 * estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
 * último byte" indica uma comparação vulnerável a timing.
 *
 * IMPORTANTE: testes de timing em PHP têm MUITO ruído (garbage collector,
 * JIT, agendamento do SO). Isso é uma checagem heurística grosseira, não
 * uma prova formal - trate qualquer resultado "vulnerável" como um convite
 * pra investigar o código-fonte diretamente, e um resultado "resistiu" como
 * "não detectei nesse experimento", não como garantia.
 */
class AtaqueTiming implements AtaqueInterface
{
    public function __construct(private int $repeticoesPorGrupo = 400)
    {
    }

    public function nome(): string
    {
        return 'Timing da verificação de integridade';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Seguranca\SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $token = $alvo->encrypt('MENSAGEM_PARA_TESTE_DE_TIMING');
        $decodificado = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
        $campos = $alvo->decompor($decodificado);
        $tamanhoIntegridade = strlen($campos['integridade']);

        $medirGrupo = function (int $posicaoErro) use ($alvo, $campos, $tamanhoIntegridade) {
            $tempos = [];
            for ($r = 0; $r < $this->repeticoesPorGrupo; $r++) {
                $camposAdulterados = $campos;
                $integ = $camposAdulterados['integridade'];
                $integ[$posicaoErro] = chr(ord($integ[$posicaoErro]) ^ 0x01);
                $camposAdulterados['integridade'] = $integ;

                $tokenAdulterado = $alvo->prefixo() . $alvo->base64urlEncode($alvo->recompor($camposAdulterados));

                $inicio = hrtime(true);
                try {
                    $alvo->decrypt($tokenAdulterado);
                } catch (\Throwable $e) {
                    // esperado
                }
                $tempos[] = hrtime(true) - $inicio;
            }
            sort($tempos);
            // usa a mediana em vez da média - muito mais robusta a outliers
            // de agendamento do SO, comum em testes de timing em ambiente
            // compartilhado.
            return $tempos[(int) (count($tempos) / 2)];
        };

        // Grupo A: erro logo no primeiro byte do campo de integridade.
        // Grupo B: erro no último byte.
        // Repete várias rodadas intercaladas pra diluir variação de carga
        // da máquina ao longo do tempo (evita viés de "a máquina esquentou").
        $medianasA = [];
        $medianasB = [];
        for ($rodada = 0; $rodada < 8; $rodada++) {
            $medianasA[] = $medirGrupo(0);
            $medianasB[] = $medirGrupo($tamanhoIntegridade - 1);
        }

        $medianaA = array_sum($medianasA) / count($medianasA);
        $medianaB = array_sum($medianasB) / count($medianasB);
        $diferencaRelativa = abs($medianaA - $medianaB) / max($medianaA, $medianaB);

        // Limite arbitrário e conservador: só marca como suspeito se a
        // diferença for grande o bastante pra não ser só ruído de máquina
        // (na prática, comparações vulneráveis costumam mostrar diferenças
        // bem mais óbvias que isso quando o campo é curto).
        $vulneravel = $diferencaRelativa > 0.15;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'media' : 'info',
            detalhes: sprintf(
                'mediana erro-no-início=%.0fns, mediana erro-no-fim=%.0fns, diferença relativa=%.1f%% (limite=15%%). %s',
                $medianaA,
                $medianaB,
                $diferencaRelativa * 100,
                $vulneravel
                    ? 'Diferença suspeita - investigar se a comparação usa hash_equals().'
                    : 'Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal).'
            ),
            dados: ['mediana_inicio_ns' => $medianaA, 'mediana_fim_ns' => $medianaB],
        );
    }
}

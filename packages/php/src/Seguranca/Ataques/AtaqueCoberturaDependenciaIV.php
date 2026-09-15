<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
 * o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
 * posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
 */
class AtaqueCoberturaDependenciaIV implements AtaqueInterface
{
    public function __construct(private int $tamanhoBloco = 32, private int $perturbacoesPorPosicao = 5)
    {
    }

    public function nome(): string
    {
        return 'Cobertura de dependência do IV (entrada x saída)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $tamanhoIv = $alvo->tamanhoIv();
        $ivBase = str_repeat("\x00", $tamanhoIv);

        $ksBase = $alvo->gerarKeystreamBruto($chave, $ivBase, 'enc', $this->tamanhoBloco);
        if ($ksBase === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $paresIndependentes = [];

        for ($posIv = 0; $posIv < $tamanhoIv; $posIv++) {
            $afetou = array_fill(0, $this->tamanhoBloco, false);

            for ($p = 0; $p < $this->perturbacoesPorPosicao; $p++) {
                $iv = $ivBase;
                $iv[$posIv] = chr(random_int(1, 255));
                $ks = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanhoBloco);

                for ($posSaida = 0; $posSaida < $this->tamanhoBloco; $posSaida++) {
                    if ($ks[$posSaida] !== $ksBase[$posSaida]) {
                        $afetou[$posSaida] = true;
                    }
                }
            }

            foreach ($afetou as $posSaida => $ok) {
                if (!$ok) {
                    $paresIndependentes[] = "iv[$posIv] -> saida[$posSaida]";
                }
            }
        }

        if (!empty($paresIndependentes)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'alta',
                detalhes: count($paresIndependentes) . " par(es) sem dependência detectável em {$this->perturbacoesPorPosicao} tentativas cada",
                dados: ['pares' => array_slice($paresIndependentes, 0, 20)],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Todas as $tamanhoIv posições do IV influenciam todas as {$this->tamanhoBloco} posições de saída",
        );
    }
}

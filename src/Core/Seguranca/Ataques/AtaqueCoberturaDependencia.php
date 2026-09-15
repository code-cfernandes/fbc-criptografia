<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
 * de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
 * pra evitar falso-positivo por coincidência de valor). Uma dependência
 * ausente indica que a mistura não se propagou completamente - um atacante
 * poderia isolar e atacar aquele par de posições separadamente do resto.
 */
class AtaqueCoberturaDependencia implements AtaqueInterface
{
    public function __construct(
        private int $tamanhoBloco = 32,
        private int $perturbacoesPorPar = 5,
    ) {
    }

    public function nome(): string
    {
        return 'Cobertura de dependência (matriz entrada x saída)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tamanho = $this->tamanhoBloco;
        $chaveBase = str_repeat("\x00", $tamanho);
        $iv = random_bytes($alvo->tamanhoIv());

        $ksBase = $alvo->gerarKeystreamBruto($chaveBase, $iv, 'enc', $tamanho);
        if ($ksBase === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }
        if (strlen($chaveBase) !== $tamanho) {
            // A chave precisa ter o mesmo tamanho do bloco pra esse teste
            // isolar 1 posição de cada vez sem wraparound. Se a cifra usa
            // chave de outro tamanho, pula esse ataque.
            throw new SkipAtaqueException('Teste requer chave do mesmo tamanho do bloco.');
        }

        $paresIndependentes = [];

        for ($posEntrada = 0; $posEntrada < $tamanho; $posEntrada++) {
            $afetouAlgumaSaida = array_fill(0, $tamanho, false);

            for ($p = 0; $p < $this->perturbacoesPorPar; $p++) {
                $chaveTeste = $chaveBase;
                $chaveTeste[$posEntrada] = chr(random_int(1, 255));
                $ks = $alvo->gerarKeystreamBruto($chaveTeste, $iv, 'enc', $tamanho);

                for ($posSaida = 0; $posSaida < $tamanho; $posSaida++) {
                    if ($ks[$posSaida] !== $ksBase[$posSaida]) {
                        $afetouAlgumaSaida[$posSaida] = true;
                    }
                }
            }

            foreach ($afetouAlgumaSaida as $posSaida => $afetou) {
                if (!$afetou) {
                    $paresIndependentes[] = "entrada[$posEntrada] -> saída[$posSaida]";
                }
            }
        }

        if (!empty($paresIndependentes)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'media',
                detalhes: count($paresIndependentes) . " par(es) sem dependência detectável em {$this->perturbacoesPorPar} tentativas cada",
                dados: ['pares' => array_slice($paresIndependentes, 0, 20)],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Todos os " . ($tamanho * $tamanho) . " pares (entrada, saída) mostraram dependência",
        );
    }
}

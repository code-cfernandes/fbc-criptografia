<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Esse é o ataque que pegou o bug mais sério que encontramos: quando a
 * distância de mistura era exatamente metade do bloco, TODOS os IVs
 * aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
 * Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
 */
class AtaqueFoldEstrutural implements AtaqueInterface
{
    public function __construct(private int $amostras = 5000, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Fold estrutural (metades/quartos/oitavos repetidos)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $primeiro = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $divisores = array_filter([2, 4, 8, 16], fn($d) => $this->tamanhoBloco % $d === 0 && $this->tamanhoBloco / $d >= 1);
        $ocorrencias = array_fill_keys($divisores, 0);

        // Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
        // a chance de colisão por acaso é ~1/256^tam por par comparado -
        // desprezível para tam >= 2, então qualquer contagem > 0 já é
        // suspeita o bastante pra investigar (ajustamos a margem pra
        // fatias de 1-2 bytes, onde colisão por acaso é mais provável).
        for ($i = 0; $i < $this->amostras; $i++) {
            $ks = $alvo->gerarKeystreamBruto($chave, random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanhoBloco);
            foreach ($divisores as $divisor) {
                $tamFatia = intdiv($this->tamanhoBloco, $divisor);
                $primeira = substr($ks, 0, $tamFatia);
                for ($j = 1; $j < $divisor; $j++) {
                    if (substr($ks, $j * $tamFatia, $tamFatia) === $primeira) {
                        $ocorrencias[$divisor]++;
                        break;
                    }
                }
            }
        }

        $margem = fn($divisor) => $this->tamanhoBloco / $divisor <= 2 ? (int) ($this->amostras * 0.01) + 3 : 5;

        $problemas = [];
        foreach ($ocorrencias as $divisor => $c) {
            if ($c > $margem($divisor)) {
                $problemas[$divisor] = $c;
            }
        }

        if (!empty($problemas)) {
            $detalhe = implode(', ', array_map(
                fn($d, $c) => "1/$d do bloco repetido em $c/{$this->amostras}",
                array_keys($problemas),
                $problemas
            ));
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: $detalhe,
                dados: ['ocorrencias' => $ocorrencias],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Nenhuma repetição estrutural acima do ruído esperado: ' . json_encode($ocorrencias),
        );
    }
}

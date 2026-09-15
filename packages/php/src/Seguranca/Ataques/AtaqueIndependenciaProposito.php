<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
 * chave do MAC ('mac'). Se os dois streams não forem independentes, um
 * atacante que recupere o keystream de dados (ataque de texto conhecido)
 * pode derivar a chave do MAC e FORJAR tokens válidos.
 *
 * O teste procura dois sintomas de acoplamento:
 *  1. a distância de Hamming média entre os streams deve ser ~50%;
 *  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
 *     uma máscara fixa, o mac é 100% previsível a partir do enc.
 */
class AtaqueIndependenciaProposito implements AtaqueInterface
{
    public function __construct(private int $amostras = 2000, private int $tamanho = 32)
    {
    }

    public function nome(): string
    {
        return 'Independência entre keystreams de propósitos diferentes (enc x mac)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $primeiro = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($alvo->tamanhoIv()), 'enc', $this->tamanho);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $distancias = [];
        $mascaras = [];
        for ($i = 0; $i < $this->amostras; $i++) {
            $chave = random_bytes(strlen($alvo->chaveDeTeste()));
            $iv = random_bytes($alvo->tamanhoIv());

            $enc = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanho);
            $mac = $alvo->gerarKeystreamBruto($chave, $iv, 'mac', $this->tamanho);

            $distancias[] = $this->bitsDiferentes($enc, $mac) / ($this->tamanho * 8);
            $mascaras[$this->xorBytes($enc, $mac)] = true;
        }

        $media = array_sum($distancias) / count($distancias);
        $mascarasDistintas = count($mascaras);

        $vulneravel = $media < 0.40 || $media > 0.60 || $mascarasDistintas < $this->amostras;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: sprintf(
                'Hamming médio enc x mac=%.1f%% (esperado ~50%%); %d máscara(s) XOR distinta(s) em %d amostras%s',
                $media * 100,
                $mascarasDistintas,
                $this->amostras,
                $mascarasDistintas < $this->amostras ? ' - MÁSCARA REPETIDA: mac previsível a partir de enc!' : '',
            ),
            dados: ['media' => $media, 'mascaras_distintas' => $mascarasDistintas],
        );
    }

    private function xorBytes(string $a, string $b): string
    {
        $out = '';
        $len = min(strlen($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $out;
    }

    private function bitsDiferentes(string $a, string $b): int
    {
        $diff = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $diff += substr_count(decbin(ord($a[$i]) ^ ord($b[$i])), '1');
        }
        return $diff;
    }
}

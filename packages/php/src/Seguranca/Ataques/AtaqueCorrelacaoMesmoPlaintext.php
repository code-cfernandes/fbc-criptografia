<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;

/**
 * O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
 * Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
 * venham do mesmo texto, se comportam como se fossem de textos diferentes
 * (distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).
 *
 * Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
 * parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
 * cifrar 500 textos diferentes.
 */
class AtaqueCorrelacaoMesmoPlaintext implements AtaqueInterface
{
    public function __construct(private int $amostras = 300, private string $textoFixo = 'MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR')
    {
    }

    public function nome(): string
    {
        return 'Correlação entre ciphertexts do mesmo plaintext';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Seguranca\SkipAtaqueException('Precisa de base64url_decode do alvo.');
        }

        $ciphertexts = [];
        for ($i = 0; $i < $this->amostras; $i++) {
            $token = $alvo->encrypt($this->textoFixo);
            $decodificado = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
            $ciphertexts[] = $alvo->decompor($decodificado)['ciphertext'];
        }

        // Compara pares aleatórios de ciphertexts (não todos contra todos,
        // pra manter o custo baixo) e mede a distância de Hamming média.
        $comparacoes = min(500, (int) ($this->amostras * ($this->amostras - 1) / 2));
        $distancias = [];
        for ($c = 0; $c < $comparacoes; $c++) {
            $i = random_int(0, $this->amostras - 1);
            $j = random_int(0, $this->amostras - 1);
            if ($i === $j) {
                continue;
            }
            $distancias[] = $this->distanciaHammingRelativa($ciphertexts[$i], $ciphertexts[$j]);
        }

        $media = array_sum($distancias) / count($distancias);

        // Também confere que nenhum PAR de ciphertexts é idêntico (o que
        // indicaria reuso de IV+key, capturado de outro ângulo).
        $duplicatas = count($ciphertexts) - count(array_unique($ciphertexts));

        $vulneravel = $media < 0.40 || $media > 0.60 || $duplicatas > 0;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: sprintf(
                'distância de Hamming média entre ciphertexts do mesmo texto: %.1f%% (esperado ~50%%), %d duplicata(s) exata(s) em %d amostras',
                $media * 100,
                $duplicatas,
                $this->amostras
            ),
            dados: ['media' => $media, 'duplicatas' => $duplicatas],
        );
    }

    private function distanciaHammingRelativa(string $a, string $b): float
    {
        $len = min(strlen($a), strlen($b));
        if ($len === 0) {
            return 0.5;
        }
        $diff = 0;
        for ($i = 0; $i < $len; $i++) {
            $diff += substr_count(decbin(ord($a[$i]) ^ ord($b[$i])), '1');
        }
        return $diff / ($len * 8);
    }
}
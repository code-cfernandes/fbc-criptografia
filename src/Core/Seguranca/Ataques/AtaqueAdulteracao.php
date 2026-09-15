<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
 * token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
 * sucesso", a cifra não está autenticando o conteúdo - é a falha que
 * encontramos e corrigimos várias vezes ao longo dessa conversa.
 */
class AtaqueAdulteracao implements AtaqueInterface
{
    public function __construct(private int $tentativas = 500)
    {
    }

    public function nome(): string
    {
        return 'Adulteração de bits (integridade)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Core\Seguranca\SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $aceitosIndevidamente = [];

        for ($t = 0; $t < $this->tentativas; $t++) {
            $texto = "MSG_$t" . str_repeat('X', random_int(0, 50));
            $token = $alvo->encrypt($texto);
            $decodificado = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
            $campos = $alvo->decompor($decodificado);

            $nomeCampo = array_rand($campos);
            $valor = $campos[$nomeCampo];
            if ($valor === '') {
                continue;
            }
            $pos = random_int(0, strlen($valor) - 1);
            $valor[$pos] = chr(ord($valor[$pos]) ^ (1 << random_int(0, 7)));
            $campos[$nomeCampo] = $valor;

            $tokenAdulterado = $alvo->prefixo() . $alvo->base64urlEncode($alvo->recompor($campos));

            try {
                $resultado = $alvo->decrypt($tokenAdulterado);
                $aceitosIndevidamente[] = "campo=$nomeCampo, texto original=$texto, resultado aceito=$resultado";
            } catch (\Throwable $e) {
                // esperado - a adulteração deveria ser rejeitada
            }
        }

        if (!empty($aceitosIndevidamente)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: count($aceitosIndevidamente) . " de {$this->tentativas} tokens adulterados foram ACEITOS",
                dados: ['exemplos' => array_slice($aceitosIndevidamente, 0, 5)],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Todas as {$this->tentativas} adulterações foram rejeitadas",
        );
    }
}

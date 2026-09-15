<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
 * garantias de confidencialidade (keystream reusado = "two-time pad").
 * Gera muitos tokens do MESMO texto e verifica se os IVs nunca colidem.
 */
class AtaqueColisaoIV implements AtaqueInterface
{
    public function __construct(private int $geracoes = 5000)
    {
    }

    public function nome(): string
    {
        return 'Colisão de IV';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Core\Seguranca\SkipAtaqueException('Precisa de base64url_decode do alvo.');
        }

        $vistos = [];
        $colisoes = 0;

        for ($i = 0; $i < $this->geracoes; $i++) {
            $token = $alvo->encrypt('MESMO_TEXTO_SEMPRE');
            $decodificado = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
            $iv = $alvo->decompor($decodificado)['iv'];
            if (isset($vistos[$iv])) {
                $colisoes++;
            }
            $vistos[$iv] = true;
        }

        if ($colisoes > 0) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: "$colisoes colisão(ões) de IV em {$this->geracoes} gerações",
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "0 colisões em {$this->geracoes} gerações",
        );
    }
}

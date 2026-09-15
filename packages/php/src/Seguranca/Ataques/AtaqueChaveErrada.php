<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;

/**
 * Garante que um token só decifra com a chave correta: com qualquer outra
 * chave de 32 bytes, decrypt() tem que lançar. Verifica também que a chave
 * errada não "quase funciona" (ex: aceitar às vezes por MAC fraco).
 *
 * Cuidado: CriptografiaAlvo escreve a chave no ambiente do processo; a chave
 * original é restaurada no final pra não afetar os outros ataques.
 */
class AtaqueChaveErrada implements AtaqueInterface
{
    public function __construct(private int $tentativas = 30)
    {
    }

    public function nome(): string
    {
        return 'Rejeição de chave incorreta';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Seguranca\SkipAtaqueException('Precisa de CriptografiaAlvo para trocar a chave.');
        }

        $chaveOriginal = $alvo->chaveDeTeste();

        $tokens = [];
        for ($i = 0; $i < $this->tentativas; $i++) {
            $tokens[] = $alvo->encrypt("MENSAGEM_SECRETA_$i");
        }

        $aceitos = [];
        try {
            foreach ($tokens as $i => $token) {
                new CriptografiaAlvo(bin2hex(random_bytes(16)));
                try {
                    $r = $alvo->decrypt($token);
                    $aceitos[] = "tentativa $i aceitou (retornou $r)";
                } catch (\Throwable $e) {
                    // esperado
                }
            }
        } finally {
            putenv('FBC_KEY=' . $chaveOriginal);
        }

        if (!empty($aceitos)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: count($aceitos) . " de {$this->tentativas} tokens foram aceitos com a chave errada",
                dados: ['exemplos' => array_slice($aceitos, 0, 5)],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Nenhum dos {$this->tentativas} tokens foi aceito com chave incorreta",
        );
    }
}

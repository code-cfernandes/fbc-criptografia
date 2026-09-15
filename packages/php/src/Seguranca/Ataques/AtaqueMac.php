<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
 * (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
 * Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
 */
class AtaqueMac implements AtaqueInterface
{
    public function __construct(private string $mensagem = 'mensagem para o ataque de MAC')
    {
    }

    public function nome(): string
    {
        return 'Força bruta e truncamento do MAC';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $token = $alvo->encrypt($this->mensagem);
        $decoded = $alvo->base64urlDecode(substr($token, strlen($alvo->prefixo())));
        $campos = $alvo->decompor($decoded);

        $montar = function (string $integridade) use ($alvo, $campos): string {
            return $alvo->prefixo() . $alvo->base64urlEncode($alvo->recompor([
                'integridade' => $integridade,
                'ciphertext' => $campos['ciphertext'],
                'iv' => $campos['iv'],
            ]));
        };

        $aceitos = [];

        // 1) integridade zerada
        try {
            $alvo->decrypt($montar(str_repeat("\x00", strlen($campos['integridade']))));
            $aceitos[] = 'integridade zerada';
        } catch (\Throwable $e) {
            // esperado
        }

        // 2) integridade truncada pela metade
        try {
            $alvo->decrypt($montar(substr($campos['integridade'], 0, 16)));
            $aceitos[] = 'integridade truncada (16 bytes)';
        } catch (\Throwable $e) {
            // esperado
        }

        // 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
        // que reconstruiria o próprio token válido e não é uma forja)
        $base = $campos['integridade'];
        for ($v = 0; $v < 256; $v++) {
            if ($v === ord($base[0])) {
                continue;
            }
            $tentativa = $base;
            $tentativa[0] = chr($v);
            try {
                $alvo->decrypt($montar($tentativa));
                $aceitos[] = "byte 0 do MAC = $v";
            } catch (\Throwable $e) {
                // esperado
            }
        }

        $vulneravel = !empty($aceitos);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: $vulneravel
                ? count($aceitos) . ' variante(s) de MAC aceitas: ' . implode('; ', array_slice($aceitos, 0, 5))
                : 'Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita',
            dados: ['aceitos' => $aceitos],
        );
    }
}

<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Length extension / truncamento: a estrutura do token é
 * integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
 * Truncar, estender ou deslocar bytes não pode produzir um token aceito.
 */
class AtaqueLengthExtension implements AtaqueInterface
{
    public function __construct(private string $mensagem = 'texto para o ataque de length extension')
    {
    }

    public function nome(): string
    {
        return 'Length extension / truncamento de token';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $prefixo = $alvo->prefixo();
        $token = $alvo->encrypt($this->mensagem);
        $corpo = substr($token, strlen($prefixo));
        $meio = intdiv(strlen($corpo), 2);

        $variantes = [
            'append A' => $prefixo . $corpo . 'A',
            'append =' => $prefixo . $corpo . '=',
            'truncar 1 char' => $prefixo . substr($corpo, 0, -1),
            'truncar 2 chars' => $prefixo . substr($corpo, 0, -2),
            'inserir ! no meio' => $prefixo . substr($corpo, 0, $meio) . '!' . substr($corpo, $meio),
            'prefixo extra' => $prefixo . 'A' . $corpo,
        ];

        // variantes que mexem nos campos decodificados
        try {
            $decoded = $alvo->base64urlDecode($corpo);
            $campos = $alvo->decompor($decoded);

            $ctMaior = $campos['ciphertext'] . chr(0x41);
            $variantes['ciphertext +1 byte'] = $prefixo . $alvo->base64urlEncode($alvo->recompor([
                'integridade' => $campos['integridade'],
                'ciphertext' => $ctMaior,
                'iv' => $campos['iv'],
            ]));

            $ctMenor = substr($campos['ciphertext'], 0, max(0, strlen($campos['ciphertext']) - 1));
            $variantes['ciphertext -1 byte'] = $prefixo . $alvo->base64urlEncode($alvo->recompor([
                'integridade' => $campos['integridade'],
                'ciphertext' => $ctMenor,
                'iv' => $campos['iv'],
            ]));

            $ivMaior = $campos['iv'] . chr(0x42);
            $variantes['iv +1 byte'] = $prefixo . $alvo->base64urlEncode($alvo->recompor([
                'integridade' => $campos['integridade'],
                'ciphertext' => $campos['ciphertext'],
                'iv' => $ivMaior,
            ]));
        } catch (\Throwable $e) {
            // se a decodificação falhar, segue com as variantes textuais
        }

        $aceitas = [];
        foreach ($variantes as $nome => $v) {
            if ($v === $token) {
                continue;
            }
            try {
                $alvo->decrypt($v);
                $aceitas[] = $nome;
            } catch (\Throwable $e) {
                // esperado
            }
        }

        $vulneravel = !empty($aceitas);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: $vulneravel
                ? count($aceitas) . ' variante(s) aceita(s): ' . implode('; ', $aceitas)
                : 'Todas as ' . count($variantes) . ' variantes de truncamento/extensão foram rejeitadas',
            dados: ['aceitas' => $aceitas],
        );
    }
}

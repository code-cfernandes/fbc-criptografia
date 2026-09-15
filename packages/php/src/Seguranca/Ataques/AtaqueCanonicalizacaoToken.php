<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\ResultadoAtaque;

/**
 * Um mesmo token não deveria ter múltiplas representações textuais válidas.
 * Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
 * padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
 * lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
 * token. Isso é "token smuggling": sistemas que comparam/usam a string do
 * token de formas diferentes (cache, WAF, deduplicação/replay) discordam
 * sobre o que ele significa.
 */
class AtaqueCanonicalizacaoToken implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Canonicalização do token (base64 não-canônico)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Seguranca\SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $texto = 'MENSAGEM_DE_TESTE_DE_CANONICALIZACAO';
        $token = $alvo->encrypt($texto);
        $prefixo = $alvo->prefixo();
        $corpo = substr($token, strlen($prefixo));
        $meio = intdiv(strlen($corpo), 2);

        $variantes = [];
        foreach ([0, $meio, strlen($corpo) - 1] as $p) {
            $variantes["espaço na posição $p"] = $prefixo . substr($corpo, 0, $p) . ' ' . substr($corpo, $p);
            $variantes["newline na posição $p"] = $prefixo . substr($corpo, 0, $p) . "\n" . substr($corpo, $p);
            $variantes["tab na posição $p"] = $prefixo . substr($corpo, 0, $p) . "\t" . substr($corpo, $p);
        }
        $variantes['alfabeto padrão (+/)'] = $prefixo . strtr($corpo, '-_', '+/');
        $variantes['padding "=" extra'] = $prefixo . $corpo . '=';
        $variantes['caractere inválido no meio'] = $prefixo . substr($corpo, 0, $meio) . '!' . substr($corpo, $meio);

        $aceitas = [];
        foreach ($variantes as $nome => $v) {
            if ($v === $token) {
                continue;
            }
            try {
                if ($alvo->decrypt($v) === $texto) {
                    $aceitas[] = $nome;
                }
            } catch (\Throwable $e) {
                // esperado
            }
        }

        if (!empty($aceitas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'media',
                detalhes: count($aceitas) . ' variante(s) textualmente diferente(s) decifram para o mesmo texto: ' . implode('; ', $aceitas),
                dados: ['variantes_aceitas' => $aceitas],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Todas as ' . count($variantes) . ' variantes não-canônicas foram rejeitadas',
        );
    }
}

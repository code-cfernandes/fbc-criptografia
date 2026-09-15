<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
 * rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
 * bytes válida deve funcionar. Uma validação frouxa aqui vira uma chave mais
 * curta (e mais fraca) na prática.
 */
class AtaqueValidacaoChave implements AtaqueInterface
{
    public function __construct(private array $tamanhos = [0, 1, 16, 31, 33, 64])
    {
    }

    public function nome(): string
    {
        return 'Validação do tamanho da chave';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Core\Seguranca\SkipAtaqueException('Precisa de CriptografiaAlvo para trocar a chave.');
        }

        $chaveOriginal = $alvo->chaveDeTeste();
        $aceitasIndevidamente = [];
        $validaRejeitada = false;

        try {
            foreach ($this->tamanhos as $len) {
                new CriptografiaAlvo(str_repeat('K', $len));
                try {
                    $alvo->encrypt('x');
                    $aceitasIndevidamente[] = $len;
                } catch (\Throwable $e) {
                    // esperado
                }
            }

            new CriptografiaAlvo(str_repeat('K', 32));
            try {
                $alvo->encrypt('x');
            } catch (\Throwable $e) {
                $validaRejeitada = true;
            }
        } finally {
            putenv('IA_CRIPT_KEY_NKC=' . $chaveOriginal);
        }

        $vulneravel = !empty($aceitasIndevidamente) || $validaRejeitada;

        $detalhes = [];
        if (!empty($aceitasIndevidamente)) {
            $detalhes[] = 'chaves de tamanho inválido aceitas: ' . implode(', ', $aceitasIndevidamente);
        }
        if ($validaRejeitada) {
            $detalhes[] = 'chave válida de 32 bytes foi rejeitada';
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'alta' : 'info',
            detalhes: $vulneravel
                ? implode('; ', $detalhes)
                : 'Tamanhos inválidos rejeitados e chave de 32 bytes aceita',
        );
    }
}

<?php

namespace Application\Core\Seguranca;

/**
 * Resultado de rodar um ataque contra um alvo.
 *
 * $vulneravel = true significa que o ataque ACHOU um problema (a cifra falhou).
 * $vulneravel = false significa que a cifra resistiu a esse ataque específico.
 */
final class ResultadoAtaque
{
    public function __construct(
        public readonly string $nomeAtaque,
        public readonly bool $vulneravel,
        public readonly string $severidade, // 'critica' | 'alta' | 'media' | 'baixa' | 'info' | 'pulado' | 'demonstracao' | 'erro'
        public readonly string $detalhes,
        public readonly ?array $dados = null, // números brutos, pra quem quiser inspecionar mais
    ) {
    }

    public function linhaResumo(): string
    {
        $status = match ($this->severidade) {
            'pulado' => 'PULADO',
            'demonstracao' => 'DEMONSTRAÇÃO',
            default => $this->vulneravel ? '❌ VULNERÁVEL' : '✅ resistiu',
        };
        return sprintf("[%s] %s (%s): %s", $status, $this->nomeAtaque, $this->severidade, $this->detalhes);
    }
}

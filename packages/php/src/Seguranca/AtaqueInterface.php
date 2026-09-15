<?php

namespace Application\Seguranca;

interface AtaqueInterface
{
    public function nome(): string;

    /**
     * Roda o ataque contra o alvo e retorna o resultado.
     * Deve lançar SkipAtaqueException se o alvo não suportar os recursos
     * necessários (ex: não expõe gerarKeystreamBruto).
     */
    public function executar(AlvoCriptografico $alvo): ResultadoAtaque;
}

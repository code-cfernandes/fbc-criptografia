<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Procura colisões no checksum() via paradoxo do aniversário: gera muitas
 * mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
 * propósito aqui - testar resistência a colisão é uma propriedade do
 * ALGORITMO, independente de a chave ser secreta ou não; é assim que se
 * testa qualquer função de hash/MAC na prática).
 *
 * Testa dois níveis:
 * 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
 *    aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
 *    tentativas pelo paradoxo do aniversário).
 * 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
 *    estatisticamente com poucas dezenas de milhares de tentativas (o
 *    paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
 *    pra 50% de chance). Isso não quebra o MAC completo (que depende dos
 *    32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
 *    útil pra saber se a composição das rodadas está de fato preservando
 *    a força total, ou se há alguma correlação entre elas.
 */
class AtaqueColisaoChecksum implements AtaqueInterface
{
    public function __construct(private int $amostras = 200000)
    {
    }

    public function nome(): string
    {
        return 'Colisão no checksum (paradoxo do aniversário)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveDeMac = str_repeat('M', 32); // chave conhecida de propósito - ver docblock

        $primeiro = $alvo->checksumBruto('teste', $chaveDeMac);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
        }

        $vistosCompleto = [];
        $vistosTruncado = [];
        $colisaoCompleta = null;
        $colisaoTruncada = null;

        for ($i = 0; $i < $this->amostras; $i++) {
            $mensagem = random_bytes(20);
            $hash = $alvo->checksumBruto($mensagem, $chaveDeMac);

            if ($colisaoCompleta === null) {
                if (isset($vistosCompleto[$hash])) {
                    $colisaoCompleta = [$vistosCompleto[$hash], $mensagem];
                } else {
                    $vistosCompleto[$hash] = $mensagem;
                }
            }

            if ($colisaoTruncada === null) {
                $truncado = substr($hash, 0, 4);
                if (isset($vistosTruncado[$truncado])) {
                    $colisaoTruncada = [$vistosTruncado[$truncado], $mensagem];
                } else {
                    $vistosTruncado[$truncado] = $mensagem;
                }
            }

            if ($colisaoCompleta !== null && $colisaoTruncada !== null) {
                break;
            }
        }

        // Colisão no checksum COMPLETO com essa amostra pequena seria uma
        // falha estrutural séria (a probabilidade por acaso é desprezível).
        if ($colisaoCompleta !== null) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: 'COLISÃO COMPLETA encontrada em ' . count($vistosCompleto) . ' amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.',
                dados: ['msg1_hex' => bin2hex($colisaoCompleta[0]), 'msg2_hex' => bin2hex($colisaoCompleta[1])],
            );
        }

        // Colisão truncada (32 bits) é esperada estatisticamente - não é
        // "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
        // força que deveriam ter (nem mais, nem menos).
        $infoTruncada = $colisaoTruncada !== null
            ? 'colisão de 32 bits encontrada em ' . count($vistosTruncado) . ' amostras (esperado pelo paradoxo do aniversário)'
            : 'nenhuma colisão de 32 bits em ' . count($vistosTruncado) . ' amostras (um pouco abaixo do esperado, mas não conclusivo)';

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: "Nenhuma colisão completa em {$this->amostras} amostras (esperado). Nível truncado (32 bits): $infoTruncada.",
            dados: ['amostras_completo' => count($vistosCompleto), 'amostras_truncado' => count($vistosTruncado)],
        );
    }
}

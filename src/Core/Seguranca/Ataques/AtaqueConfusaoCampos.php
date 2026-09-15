<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\ResultadoAtaque;

/**
 * O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
 * ambíguo, um atacante pode reordenar/deslocar os campos e construir um
 * token que sistemas diferentes interpretam de formas diferentes. Todos os
 * rearranjos devem ser rejeitados pela integridade.
 */
class AtaqueConfusaoCampos implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Confusão de campos do token (reordenação/deslocamento)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        if (!$alvo instanceof CriptografiaAlvo) {
            throw new \Application\Core\Seguranca\SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
        }

        $texto = 'MENSAGEM_PARA_TESTE_DE_CAMPOS';
        $token = $alvo->encrypt($texto);
        $prefixo = $alvo->prefixo();
        $campos = $alvo->decompor($alvo->base64urlDecode(substr($token, strlen($prefixo))));

        $integridade = $campos['integridade'];
        $ciphertext = $campos['ciphertext'];
        $iv = $campos['iv'];

        $variantes = [
            'iv no início' => $iv . $integridade . $ciphertext,
            'ciphertext antes da integridade' => $ciphertext . $integridade . $iv,
            'iv duplicado no fim' => $integridade . $ciphertext . $iv . $iv,
            'integridade encurtada' => substr($integridade, 1) . $ciphertext . $iv,
            'byte extra no início' => 'X' . $integridade . $ciphertext . $iv,
            'byte extra entre integridade e ciphertext' => $integridade . 'X' . $ciphertext . $iv,
            'byte extra antes do iv' => $integridade . $ciphertext . 'X' . $iv,
            'iv rotacionado' => $integridade . $ciphertext . strrev($iv),
            'iv e último byte do ciphertext trocados' => $integridade . substr($ciphertext, 0, -1) . $iv . substr($ciphertext, -1),
        ];

        $aceitas = [];
        foreach ($variantes as $nome => $bruto) {
            $tokenVariante = $prefixo . $alvo->base64urlEncode($bruto);
            try {
                $r = $alvo->decrypt($tokenVariante);
                $aceitas[] = "$nome -> aceito (retornou " . strlen($r) . ' bytes)';
            } catch (\Throwable $e) {
                // esperado
            }
        }

        if (!empty($aceitas)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: count($aceitas) . ' rearranjo(s) de campo foram aceitos',
                dados: ['exemplos' => $aceitas],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Todos os ' . count($variantes) . ' rearranjos de campo foram rejeitados',
        );
    }
}

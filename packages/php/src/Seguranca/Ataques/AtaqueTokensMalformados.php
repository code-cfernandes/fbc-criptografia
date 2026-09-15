<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;

/**
 * Robustez do parser de tokens: qualquer entrada que não seja um token
 * íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
 * devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
 * é uma porta pra bugs de validação e "token smuggling".
 */
class AtaqueTokensMalformados implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Tokens malformados (fuzzing de entrada)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $token = $alvo->encrypt('MENSAGEM_VALIDA_PARA_TESTE');
        $prefixo = $alvo->prefixo();
        $corpo = substr($token, strlen($prefixo));

        $casos = [
            'vazio' => '',
            'só prefixo' => $prefixo,
            'prefixo errado' => 'XXX' . $corpo,
            'base64 inválido' => $prefixo . '!!!@@@###',
            'bytes extras no fim' => $token . 'AAAA',
            'bytes extras no início' => 'AAAA' . $token,
        ];
        for ($len = 1; $len < strlen($token); $len++) {
            $casos["truncado em $len"] = substr($token, 0, $len);
        }
        for ($i = 0; $i < 20; $i++) {
            $casos["lixo aleatório $i"] = $prefixo . bin2hex(random_bytes(16));
        }

        $aceitos = [];
        foreach ($casos as $nome => $t) {
            try {
                $r = $alvo->decrypt($t);
                $aceitos[] = sprintf('%s -> aceito (retornou %d bytes)', $nome, strlen($r));
            } catch (\Throwable $e) {
                // comportamento esperado
            }
        }

        if (!empty($aceitos)) {
            return new ResultadoAtaque(
                $this->nome(),
                vulneravel: true,
                severidade: 'critica',
                detalhes: count($aceitos) . ' entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas',
                dados: ['exemplos' => array_slice($aceitos, 0, 10)],
            );
        }

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: false,
            severidade: 'info',
            detalhes: 'Todas as ' . count($casos) . ' entradas malformadas foram rejeitadas',
        );
    }
}

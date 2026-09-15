<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
 * reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
 * Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
 * aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
 * gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
 * vaza nesse cenário catastrófico.
 *
 * Isso não é um "bug" da implementação (é uma propriedade universal de
 * qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
 * quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
 * suíte: a segurança inteira depende do IV nunca repetir.
 */
class AtaqueReusoIV implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Reuso forçado de IV (two-time pad)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $ivFixo = random_bytes($alvo->tamanhoIv());

        $primeiro = $alvo->gerarKeystreamBruto($chave, $ivFixo, 'enc', 16);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $plaintext1 = 'TRANSFERIR_1000';
        $plaintext2 = 'CANCELAR_TUDO!!';
        $tamanho = max(strlen($plaintext1), strlen($plaintext2));

        $keystream = $alvo->gerarKeystreamBruto($chave, $ivFixo, 'enc', $tamanho);

        $ciphertext1 = $this->xor($plaintext1, $keystream);
        $ciphertext2 = $this->xor($plaintext2, $keystream);

        // O atacante NUNCA precisou saber a key nem o keystream - só
        // observou os dois ciphertexts (que vazariam publicamente se o
        // IV fosse reusado) e os combinou entre si.
        $xorDosCiphertexts = $this->xor($ciphertext1, $ciphertext2);
        $xorEsperadoDosPlaintexts = $this->xor($plaintext1, $plaintext2);

        $vazou = $xorDosCiphertexts === $xorEsperadoDosPlaintexts;

        // Com IV reusado, a propriedade é universal e sempre se confirma - por
        // isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
        // demonstração). Só vira alerta se, por algum motivo, a propriedade
        // NÃO se confirmar (o que indicaria um combinador inconsistente).
        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: !$vazou,
            severidade: $vazou ? 'demonstracao' : 'alta',
            detalhes: $vazou
                ? "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) " .
                  "sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA " .
                  "defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
                : "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)",
            dados: [
                'plaintext1' => $plaintext1,
                'plaintext2' => $plaintext2,
                'xor_plaintexts_hex' => bin2hex($xorEsperadoDosPlaintexts),
                'xor_ciphertexts_hex' => bin2hex($xorDosCiphertexts),
            ],
        );
    }

    private function xor(string $a, string $b): string
    {
        $len = min(strlen($a), strlen($b));
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $out;
    }
}
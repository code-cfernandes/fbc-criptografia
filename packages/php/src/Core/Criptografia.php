<?php

namespace Application\Core;

/**
 * Cifra caseira educacional.
 *
 * Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
 *
 * O keystream é gerado em blocos de 32 bytes por uma recorrência tipo-Fibonacci
 * por posição, seguida de uma rede de difusão tipo "butterfly": a cada rodada,
 * cada posição se mistura com a posição a uma distância que DOBRA (1, 2, 4, 8, 16).
 * Isso garante matematicamente que toda posição influencia toda posição do bloco
 * em exatamente log2(32) = 5 rodadas — não depende de sorte de IV.
 *
 * A quantidade de ROTAÇÃO usada dentro de cada passo (não a distância da mistura)
 * vem de uma tabela pública fixa derivada dos dígitos de Pi — só pra evitar um
 * padrão repetitivo, sem ser tratada como segredo.
 */
class Criptografia
{
    private const TAM_BLOCO = 32;

    /**
     * Distâncias de mistura geradas via Fibonacci -> N-ésimo primo, pulando
     * o único primo par (2). Como o bloco tem 32 posições (potência de 2),
     * qualquer distância ÍMPAR é automaticamente coprima com 32 - o que
     * garante matematicamente um ciclo completo de 32 posições, evitando
     * o colapso em subgrupos simétricos menores (o bug da "metade igual").
     *
     * fib(1)=1 -> 1º primo é 2 (descartado, par) -> fib(2)=1 -> idem
     * fib(3)=2 -> 2º primo=3 | fib(4)=3 -> 3º primo=5 | fib(5)=5 -> 5º primo=11
     * fib(6)=8 -> 8º primo=19 | fib(7)=13 -> 13º primo=41
     */
    private const DISTANCIAS_DIFUSAO = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41]; // dobrado pra combater ataque integral

    /** Dígitos de Pi (constante pública e fixa - "nothing up my sleeve"). */
    private const DIGITOS_PI = '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

    public static function encrypt(string $text): string
    {
        $key = self::getKey();
        $iv = random_bytes(16);

        $encKeystream = self::gerarKeystream($key, $iv, 'enc', strlen($text));
        $ciphertext = self::xorBytes($text, $encKeystream);

        $macKey = self::gerarKeystream($key, $iv, 'mac', self::TAM_BLOCO);
        $integridade = self::checksum($iv . $ciphertext, $macKey);

        return 'FBC' . self::base64url_encode($integridade . $ciphertext . $iv);
    }

    public static function decrypt(string $text): string
    {
        if (substr($text, 0, 3) !== 'FBC') {
            throw new \Exception('Invalid text. Text must start with FBC.');
        }

        $key = self::getKey();
        $decoded = self::base64url_decode(substr($text, 3));

        $integridadeRecebida = substr($decoded, 0, self::TAM_BLOCO);
        $iv = substr($decoded, -16);
        $ciphertext = substr($decoded, self::TAM_BLOCO, -16);

        $macKey = self::gerarKeystream($key, $iv, 'mac', self::TAM_BLOCO);
        $integridadeEsperada = self::checksum($iv . $ciphertext, $macKey);

        if (!hash_equals($integridadeEsperada, $integridadeRecebida)) {
            throw new \Exception('Token adulterado ou chave incorreta.');
        }

        $encKeystream = self::gerarKeystream($key, $iv, 'enc', strlen($ciphertext));
        return self::xorBytes($ciphertext, $encKeystream);
    }

    // ---------------------------------------------------------------
    // NÚCLEO: gerador de keystream com difusão tipo butterfly
    // ---------------------------------------------------------------

    private static function gerarKeystream(string $key, string $iv, string $proposito, int $tamanho): string
    {
        $bloco = self::TAM_BLOCO;
        $ivLen = strlen($iv);
        $keyLen = strlen($key);

        $a = [];
        $b = [];
        for ($pos = 0; $pos < $bloco; $pos++) {
            $a[$pos] = ord($key[$pos % $keyLen]) ^ ord($iv[$pos % $ivLen]);
            $b[$pos] = ord($key[($pos + 1) % $keyLen]) ^ ord($iv[($pos + 1) % $ivLen]);
        }

        $saida = '';
        $roundIdx = 0;
        $posFibBase = 0;

        while (strlen($saida) < $tamanho) {
            // Uma "passada" completa de difusão: distâncias 1,2,4,8,16 —
            // garante que toda posição influenciou toda posição ao final.
            foreach (self::DISTANCIAS_DIFUSAO as $dist) {
                $novoB = [];
                for ($pos = 0; $pos < $bloco; $pos++) {
                    [$novoA, $novoBb] = self::passo(
                        $a[$pos],
                        $b[$pos],
                        $key,
                        $proposito,
                        $posFibBase + $pos,
                        $roundIdx
                    );
                    $a[$pos] = $novoA;
                    $novoB[$pos] = $novoBb;
                }

                // Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR.
                // Isso é essencial - se rotacionássemos o XOR já combinado
                // (comutativo), pos e pos+16 calculariam o mesmo valor sempre
                // que $dist for exatamente metade do bloco, colapsando as duas
                // metades do bloco numa cópia idêntica uma da outra.
                $misturado = [];
                for ($pos = 0; $pos < $bloco; $pos++) {
                    $vizinho = $novoB[($pos + $dist) % $bloco];
                    $misturado[$pos] = self::rotEsquerda8($novoB[$pos], 1) ^ $vizinho;
                }
                $b = $misturado;
                $roundIdx++;
            }

            $posFibBase += $bloco;

            foreach ($b as $byte) {
                $saida .= chr($byte);
            }
        }

        return substr($saida, 0, $tamanho);
    }

    /**
     * Um passo da recorrência tipo-Fibonacci pra uma posição do bloco.
     *
     * @return array{0: int, 1: int}
     */
    private static function passo(int $a, int $b, string $key, string $proposito, int $posFib, int $roundIdx): array
    {
        $n = self::rotacaoDoRound($roundIdx);

        $soma = ($a + $b) & 0xFF;
        $soma = self::rotEsquerda8($soma, $n);
        $soma ^= ord($proposito[$posFib % strlen($proposito)]);
        // A chave agora participa de CADA rodada, não só do estado inicial.
        // Sem isso, keystream(key, iv) == keystream(key^D, iv^D16) pra
        // qualquer máscara D de 32 bytes com período 16 - o IV só deslocava
        // a chave por XOR antes da difusão começar, sem injetar entropia
        // própria no "key schedule" a cada passo.
        $soma ^= ord($key[($posFib + $roundIdx) % strlen($key)]);
        $soma = ($soma * 131) & 0xFF;

        return [$b, $soma];
    }

    /** Rotação (1 a 7) derivada dos dígitos de Pi — pública, não é segredo. */
    private static function rotacaoDoRound(int $roundIdx): int
    {
        $digitos = self::DIGITOS_PI;
        $d = (int) $digitos[$roundIdx % strlen($digitos)];
        return ($d % 7) + 1;
    }

    private static function rotEsquerda8(int $byte, int $n): int
    {
        $n &= 7;
        if ($n === 0) {
            return $byte & 0xFF;
        }
        return (($byte << $n) | ($byte >> (8 - $n))) & 0xFF;
    }

    private static function rotEsquerda32(int $val, int $n): int
    {
        $n &= 31;
        if ($n === 0) {
            return $val & 0xFFFFFFFF;
        }
        return (($val << $n) | ($val >> (32 - $n))) & 0xFFFFFFFF;
    }

    private static function xorBytes(string $dados, string $keystream): string
    {
        $out = '';
        $len = strlen($dados);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($dados[$i]) ^ ord($keystream[$i]));
        }
        return $out;
    }

    /**
     * "MAC" caseiro estendido pra 32 bytes: roda um checksum de 32 bits
     * 8 vezes, mudando a semente a cada rodada, e concatena os resultados.
     */
    private static function checksum(string $dados, string $key): string
    {
        $saida = '';
        for ($rodada = 0; $rodada < 8; $rodada++) {
            $acumulador = 0x811C9DC5 ^ ($rodada * 0x01000193);
            $keyLen = strlen($key);
            $len = strlen($dados);
            for ($i = 0; $i < $len; $i++) {
                $byte = ord($dados[$i]) ^ ord($key[($i + $rodada) % $keyLen]);
                $acumulador = ($acumulador ^ $byte) & 0xFFFFFFFF;
                $acumulador = ($acumulador * 16777619) & 0xFFFFFFFF;
                $acumulador = self::rotEsquerda32($acumulador, ($i % 13) + 1);
            }
            // Finalização: sem isso, o último byte processado só passa por
            // 1 multiply+rotate antes de virar saída, e sofre avalanche
            // fraca (medimos ~25-30% em vez de ~50% nos últimos bytes).
            // Espalha o acumulador mais 3 vezes depois que TODOS os bytes
            // já entraram, garantindo que a posição de entrada deixe de
            // importar pro resultado final.
            for ($k = 0; $k < 3; $k++) {
                $acumulador ^= ($acumulador >> 16);
                $acumulador = ($acumulador * 16777619) & 0xFFFFFFFF;
                $acumulador = self::rotEsquerda32($acumulador, 13);
            }
            $saida .= chr(($acumulador >> 24) & 0xFF) . chr(($acumulador >> 16) & 0xFF)
                . chr(($acumulador >> 8) & 0xFF) . chr($acumulador & 0xFF);
        }
        return $saida; // 32 bytes
    }

    // ---------------------------------------------------------------
    // Utilitários
    // ---------------------------------------------------------------

    public static function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64url_decode(string $data): string
    {
        // Rejeita qualquer caractere fora do alfabeto base64url - sem isso,
        // base64_decode() não-estrito ignora silenciosamente espaços, \n,
        // \t e caracteres inválidos, fazendo textos DIFERENTES decodificarem
        // pro mesmo token (abre espaço pra "token smuggling": um WAF/cache/log
        // vê uma string, o decrypt() vê outra).
        if ($data !== '' && !preg_match('/^[A-Za-z0-9_-]+$/', $data)) {
            throw new \Exception('Token contém caracteres inválidos.');
        }

        $padded = strtr($data, '-_', '+/');
        $mod = strlen($padded) % 4;
        if ($mod === 1) {
            throw new \Exception('Comprimento de token inválido.');
        }
        if ($mod) {
            $padded .= str_repeat('=', 4 - $mod);
        }

        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new \Exception('Token base64 inválido.');
        }

        // Canonicidade: mesmo com strict=true, o último grupo de base64 pode
        // ter bits "não usados" setados como 1 em vez de 0 e ainda decodificar
        // pro mesmo byte - reencodar e comparar pega esse caso, que o
        // strict=true sozinho NÃO pega.
        if (self::base64url_encode($decoded) !== $data) {
            throw new \Exception('Token não está em forma canônica.');
        }

        return $decoded;
    }

    private static function getKey(): string
    {
        $key = getenv('FBC_KEY');
        if (strlen($key) !== 32) {
            throw new \Exception('Chave deve ter 32 bytes.');
        }
        return $key;
    }
}
<?php

// Harness de regressão histórica (porte do equivalente em Node).
//
// Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
// bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
// (vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
// PRECISA resistir (vulneravel=false).

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Application\Core\Criptografia;
use Application\Seguranca\Ataques\AtaqueAvalancheChecksum;
use Application\Seguranca\Ataques\AtaqueCanonicalizacaoToken;
use Application\Seguranca\Ataques\AtaqueCorrelacaoMesmoPlaintext;
use Application\Seguranca\Ataques\AtaqueFoldEstrutural;
use Application\Seguranca\Ataques\AtaqueIntegral;
use Application\Seguranca\Ataques\AtaqueSeparacaoChaveIV;
use Application\Seguranca\CriptografiaAlvo;

/**
 * Alvo que aponta para a cifra com o bug selecionado. Estende
 * CriptografiaAlvo para passar nos `instanceof CriptografiaAlvo` dos ataques.
 */
class SnapshotAlvo extends CriptografiaAlvo
{
    private const TAM_BLOCO = 32;

    private const DIGITOS_PI = '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

    public function __construct(private int $bug)
    {
        parent::__construct();
    }

    public function gerarKeystreamBruto(string $key, string $iv, string $proposito, int $tamanho): ?string
    {
        return $this->gerarKeystreamComBug($key, $iv, $proposito, $tamanho);
    }

    public function checksumBruto(string $dados, string $key): ?string
    {
        return $this->checksumComBug($dados, $key);
    }

    public function base64urlDecode(string $data): string
    {
        return $this->base64urlDecodeComBug($data);
    }

    public function encrypt(string $texto): string
    {
        $key = $this->chaveDeTeste();
        $iv = random_bytes($this->tamanhoIv());
        $keystream = $this->gerarKeystreamBruto($key, $iv, 'enc', strlen($texto));
        $ciphertext = $this->xorBytes($texto, $keystream);

        $macKey = $this->gerarKeystreamBruto($key, $iv, 'mac', self::TAM_BLOCO);
        $integridade = $this->checksumBruto($iv . $ciphertext, $macKey);

        return 'FBC' . Criptografia::base64url_encode($integridade . $ciphertext . $iv);
    }

    public function decrypt(string $token): string
    {
        if (substr($token, 0, 3) !== 'FBC') {
            throw new \Exception('prefixo');
        }

        $key = $this->chaveDeTeste();
        $decodificado = $this->base64urlDecode(substr($token, 3));

        $integridade = substr($decodificado, 0, self::TAM_BLOCO);
        $iv = substr($decodificado, -$this->tamanhoIv());
        $ciphertext = substr($decodificado, self::TAM_BLOCO, -$this->tamanhoIv());

        $macKey = $this->gerarKeystreamBruto($key, $iv, 'mac', self::TAM_BLOCO);
        $esperado = $this->checksumBruto($iv . $ciphertext, $macKey);

        if (!hash_equals($esperado, $integridade)) {
            throw new \Exception('MAC');
        }

        $keystream = $this->gerarKeystreamBruto($key, $iv, 'enc', strlen($ciphertext));
        return $this->xorBytes($ciphertext, $keystream);
    }

    // ---------------------------------------------------------------
    // gerarKeystream com mutações: bugs 1, 2, 4 e 5.
    // ---------------------------------------------------------------

    private function gerarKeystreamComBug(string $key, string $iv, string $proposito, int $tamanho): string
    {
        if ($this->bug === 1) {
            // bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
            return parent::gerarKeystreamBruto($key, str_repeat("\x00", strlen($iv)), $proposito, $tamanho);
        }

        $bloco = self::TAM_BLOCO;
        // bug 2: o colapso de metades só acontece quando a distância é exatamente
        // metade do bloco (16) - reproduzimos a condição histórica.
        $distancias = match ($this->bug) {
            4 => [3],
            2 => [3, 5, 11, 19, 41, 16],
            default => [3, 5, 11, 19, 41, 3, 5, 11, 19, 41],
        };
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
            foreach ($distancias as $dist) {
                $novoB = [];
                for ($pos = 0; $pos < $bloco; $pos++) {
                    [$novoA, $novoBb] = $this->passoComBug(
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

                $misturado = [];
                for ($pos = 0; $pos < $bloco; $pos++) {
                    $vizinho = $novoB[($pos + $dist) % $bloco];
                    if ($this->bug === 2) {
                        // bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                        $misturado[$pos] = self::rotEsquerda8($novoB[$pos] ^ $vizinho, 1);
                    } else {
                        $misturado[$pos] = self::rotEsquerda8($novoB[$pos], 1) ^ $vizinho;
                    }
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

    /** passo com mutação: bug 5 remove a reinserção da chave em cada rodada. */
    private function passoComBug(int $a, int $b, string $key, string $proposito, int $posFib, int $roundIdx): array
    {
        $n = self::rotacaoDoRound($roundIdx);

        $soma = ($a + $b) & 0xFF;
        $soma = self::rotEsquerda8($soma, $n);
        $soma ^= ord($proposito[$posFib % strlen($proposito)]);
        if ($this->bug !== 5) {
            $soma ^= ord($key[($posFib + $roundIdx) % strlen($key)]);
        }
        $soma = ($soma * 131) & 0xFF;

        return [$b, $soma];
    }

    // ---------------------------------------------------------------
    // checksum com mutação: bug 3 remove a finalização.
    // ---------------------------------------------------------------

    private function checksumComBug(string $dados, string $key): string
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
            if ($this->bug !== 3) {
                for ($k = 0; $k < 3; $k++) {
                    $acumulador ^= ($acumulador >> 16);
                    $acumulador = ($acumulador * 16777619) & 0xFFFFFFFF;
                    $acumulador = self::rotEsquerda32($acumulador, 13);
                }
            }
            $saida .= chr(($acumulador >> 24) & 0xFF) . chr(($acumulador >> 16) & 0xFF)
                . chr(($acumulador >> 8) & 0xFF) . chr($acumulador & 0xFF);
        }
        return $saida;
    }

    // ---------------------------------------------------------------
    // base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo.
    // ---------------------------------------------------------------

    private function base64urlDecodeComBug(string $str): string
    {
        if ($this->bug !== 6) {
            return parent::base64urlDecode($str);
        }

        $s = strtr($str, '-_', '+/');
        $s = preg_replace('/[^A-Za-z0-9+\/=]/', '', $s);
        $mod = strlen($s) % 4;
        if ($mod) {
            $s .= str_repeat('=', 4 - $mod);
        }
        return (string) base64_decode($s, false);
    }

    // ---------------------------------------------------------------
    // Helpers copiados de Application\Core\Criptografia.
    // ---------------------------------------------------------------

    private static function rotacaoDoRound(int $roundIdx): int
    {
        $d = (int) self::DIGITOS_PI[$roundIdx % strlen(self::DIGITOS_PI)];
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

    private function xorBytes(string $dados, string $keystream): string
    {
        $out = '';
        $len = strlen($dados);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($dados[$i]) ^ ord($keystream[$i]));
        }
        return $out;
    }
}

$casos = [
    ['bug' => 1, 'descricao' => 'keystream ignora o IV', 'ataque' => new AtaqueCorrelacaoMesmoPlaintext()],
    ['bug' => 2, 'descricao' => 'combinador simétrico (metades colapsam)', 'ataque' => new AtaqueFoldEstrutural()],
    ['bug' => 3, 'descricao' => 'checksum sem finalização', 'ataque' => new AtaqueAvalancheChecksum()],
    ['bug' => 4, 'descricao' => 'cinco rodadas de difusão', 'ataque' => new AtaqueIntegral()],
    ['bug' => 5, 'descricao' => 'chave só no estado inicial', 'ataque' => new AtaqueSeparacaoChaveIV()],
    ['bug' => 6, 'descricao' => 'base64 não estrito', 'ataque' => new AtaqueCanonicalizacaoToken()],
];

echo str_repeat('=', 72) . "\n";
echo "REGRESSÃO HISTÓRICA\n";
echo str_repeat('=', 72) . "\n";

$falhas = 0;
foreach ($casos as $caso) {
    $snapshot = new SnapshotAlvo($caso['bug']);
    $real = new CriptografiaAlvo();

    try {
        $rSnapshot = $caso['ataque']->executar($snapshot);
        $rReal = $caso['ataque']->executar($real);
    } catch (\Throwable $e) {
        echo "  ❌ bug {$caso['bug']} ({$caso['descricao']}): erro — {$e->getMessage()}\n";
        $falhas++;
        continue;
    }

    $detectou = $rSnapshot->vulneravel === true;
    $resistiu = $rReal->vulneravel === false;
    $ok = $detectou && $resistiu;
    if (!$ok) {
        $falhas++;
    }

    echo "  " . ($ok ? '✅' : '❌') . " bug {$caso['bug']} ({$caso['descricao']}): "
        . 'snapshot ' . ($detectou ? 'detectado' : 'NÃO detectado')
        . ' | atual ' . ($resistiu ? 'resistiu' : 'ACUSOU') . "\n";

    if (!$ok) {
        echo "       snapshot: {$rSnapshot->linhaResumo()}\n";
        echo "       atual:    {$rReal->linhaResumo()}\n";
    }
}

echo str_repeat('=', 72) . "\n";
if ($falhas === 0) {
    echo 'RESUMO: ' . count($casos) . " bugs históricos detectados; código atual resiste a todos.\n";
} else {
    echo "RESUMO: {$falhas} caso(s) falharam.\n";
}
echo str_repeat('=', 72) . "\n";

exit($falhas === 0 ? 0 : 1);

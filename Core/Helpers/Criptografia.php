<?php

namespace Application\Core\Helpers;

use Application\Core\Env\DotEnv;

// IV: 16 bytes aleatórios, por mensagem
// MAC: 32 bytes, derivado de key + iv + ciphertext
class Criptografia
{
  /**
   * Encrypts the given text using the provided key.
   *
   * @param string $text The text to encrypt.
   * @return string The encrypted text.
   * @throws \Exception If the key length is not 32.
   */
  public static function encrypt($text)
  {
    $key = self::getKey();

    // IV binário de 16 bytes
    $iv = random_bytes(16);

    // Deriva o "mac" (na verdade é uma chave derivada) a partir de key + iv
    $mac = self::deriveKeyFibonacciSalto($key, $iv, 'mac');

    // Semente do PRNG baseada no mac
    mt_srand(hexdec(substr(bin2hex($mac), 0, 8)));

    $encrypted = self::xor_encrypt(
      str_shuffle($text),
      str_shuffle($iv . $key)
    );

    // Layout: MAC (32) . CIPHERTEXT . IV (16)
    return 'NKC' . self::base64url_encode($mac . $encrypted . $iv);
  }

  public static function decrypt(string $text): string
  {
    if (substr($text, 0, 3) !== 'NKC') {
      throw new \Exception('Invalid text. Text must start with NKC.');
    }

    $key = self::getKey();

    $decoded = self::base64url_decode(substr($text, 3));

    // Layout: MAC (32) . CIPHERTEXT . IV (16)
    $mac        = substr($decoded, 0, 32);
    $iv         = substr($decoded, -16);
    $ciphertext = substr($decoded, 32, -16);

    // Validação do MAC (apenas key + iv, como está no encrypt)
    $macEsperado = self::deriveKeyFibonacciSalto($key, $iv, 'mac');
    if (!hash_equals($macEsperado, $mac)) {
      throw new \Exception('Token adulterado ou chave incorreta.');
    }

    $seed = hexdec(substr(bin2hex($mac), 0, 8));
    $len  = strlen($ciphertext);

    // Reproduz o consumo do str_shuffle($text) feito no encrypt
    mt_srand($seed);
    str_shuffle(str_repeat('x', $len)); // mesmo comprimento => mesmo consumo do PRNG

    $keyShuffled = str_shuffle($iv . $key);

    $shuffledText = self::xor_encrypt($ciphertext, $keyShuffled);

    // Volta ao estado inicial para desfazer o shuffle do texto
    mt_srand($seed);
    return self::str_unshuffle($shuffledText);
  }

  public static function base64url_decode(string $data): string
  {
    $data = strtr($data, '-_', '+/');
    $mod = strlen($data) % 4;
    if ($mod) {
      $data .= str_repeat('=', 4 - $mod);
    }
    return base64_decode($data);
  }

  /**
   * Checks if a given string is a valid Base64 encoded string.
   *
   * This function attempts to decode the input string and then re-encode it.
   * If the re-encoded string matches the original input (ignoring padding),
   * the input is considered a valid Base64 encoded string.
   *
   * @param string $base64 The string to be checked.
   * @return bool Returns true if the input is a valid Base64 encoded string, false otherwise.
   */
  public static function isValidBase64($base64)
  {
    try {
      return rtrim($base64, '=') === rtrim(base64_encode(base64_decode($base64)), '=');
    } catch (\Exception $e) {
      return false;
    }
  }
  /**
   * The function base64url_encode encodes data using base64 encoding with URL-safe characters.
   * @param string $data - The parameter "data" is the input data that you want to encode using the base64url encoding
   * algorithm. This can be any type of data, such as a string or binary data.
   * @return string the base64url encoded version of the input data.
   */
  public static function base64url_encode($data)
  {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function deriveKeyFibonacciSalto(string $key, string $iv, string $proposito): string
  {
    $ivLen = strlen($iv);
    $propLen = strlen($proposito);

    $a = ord($key[0]) ^ ord($iv[0]);
    $b = ord($key[1 % strlen($key)]) ^ ord($iv[1 % $ivLen]);

    $saida = '';
    $tamanho = 32;
    $posicaoFib = 0; // posição "real" dentro da sequência, avança por saltos variáveis

    for ($i = 0; $i < $tamanho; $i++) {
      // o salto vem do IV: cada byte do IV vira um número de passos a avançar
      $salto = (ord($iv[$i % $ivLen]) % 5) + 1; // entre 1 e 5 passos

      for ($s = 0; $s < $salto; $s++) {
        $soma = ($a + $b) & 0xFF;

        // ponto-chave: quebra a linearidade aqui, não deixa ser só soma
        $soma = self::rotEsquerda8($soma, 3);
        $soma ^= ord($proposito[$posicaoFib % $propLen]);
        $soma = ($soma * 131) & 0xFF;

        $a = $b;
        $b = $soma;
        $posicaoFib++;
      }

      $saida .= chr($b);
    }

    return $saida;
  }

  private static function rotEsquerda8(int $byte, int $n): int
  {
    $n &= 7;
    return (($byte << $n) | ($byte >> (8 - $n))) & 0xFF;
  }

  /**
   * Performs a bitwise XOR encryption on the given input using the provided key.
   *
   * @param string $input The input to encrypt.
   * @param string $key The encryption key.
   * @return string The encrypted output.
   */
  private static function xor_encrypt($input, $key)
  {
    if (empty($input) || empty($key)) {
      throw new \Exception('Input and key must not be empty.');
    }

    $output = '';
    for ($i = 0, $len = strlen($input); $i < $len; $i++) {
      $key = str_repeat($key, ceil(strlen($input) / strlen($key)));
      $output .= chr(ord($input[$i]) ^ ord($key[$i % $len]));
    }

    return $output;
  }
  /**
   * "MAC" caseiro: acumula todos os bytes da mensagem de forma
   * que qualquer mudança de 1 bit altere o resultado inteiro.
   * Retorna um inteiro de 32 bits.
   */
  private static function checksum(string $dados, string $key): int
  {
    $acumulador = 0x811C9DC5; // valor inicial arbitrário (não-zero)
    $keyLen = strlen($key);
    $len = strlen($dados);

    for ($i = 0; $i < $len; $i++) {
      $byte = ord($dados[$i]) ^ ord($key[$i % $keyLen]);
      $acumulador = ($acumulador ^ $byte) & 0xFFFFFFFF;
      $acumulador = (($acumulador * 16777619) & 0xFFFFFFFF); // difusão
      $acumulador = self::rotEsquerda32($acumulador, ($i % 13) + 1);
    }

    return $acumulador;
  }

  private static function intParaBytes(int $val): string
  {
    return chr(($val >> 24) & 0xFF) . chr(($val >> 16) & 0xFF)
      . chr(($val >> 8) & 0xFF)  . chr($val & 0xFF);
  }

  private static function bytesParaInt(string $bytes): int
  {
    return (ord($bytes[0]) << 24) | (ord($bytes[1]) << 16)
      | (ord($bytes[2]) << 8)  | ord($bytes[3]);
  }

  private static function rotEsquerda32(int $val, int $n): int
  {
    $n &= 31;
    return (($val << $n) | ($val >> (32 - $n))) & 0xFFFFFFFF;
  }

  private static function str_unshuffle(string $str): string
  {
    $unique = implode(array_map('chr', range(0, 254)));
    $none   = chr(255);
    $slen   = strlen($str);
    $c      = intval(ceil($slen / 255));
    $r      = '';
    for ($i = 0; $i < $c; $i++) {
      $aaa = str_repeat($none, $i * 255);
      $bbb = (($i + 1) < $c) ? $unique : substr($unique, 0, $slen % 255);
      $ccc = (($i + 1) < $c) ? str_repeat($none, strlen($str) - ($i + 1) * 255) : "";
      $tmp = $aaa . $bbb . $ccc;
      $sh  = str_shuffle($tmp);
      for ($j = 0; $j < strlen($bbb); $j++) {
        $r .= $str[strpos($sh, $unique[$j])];
      }
    }
    return $r;
  }

  private static function getKey(): string
  {
    $key = DotEnv::get('IA_CRIPT_KEY_NKC');
    if (strlen($key) !== 32) {
      throw new \Exception('Chave deve ter 32 bytes.');
    }
    return $key;
  }
}

<?php

namespace Application\Core\Helpers;

use Application\Core\Env\DotEnv;

class Criptografia
{
  public static function encrypt(string $text): string
  {
    $key = self::getKey();
    $iv  = random_bytes(16); // aleatório de verdade, por mensagem

    $ciphertext = self::xorStream($text, $key, $iv);
    $mac        = self::checksum($iv . $ciphertext, self::deriveKey($key, 'mac'));

    // tudo em binário puro: iv + ciphertext + mac (4 bytes)
    $payload = $iv . $ciphertext . self::intParaBytes($mac);

    return 'NKC' . self::base64url_encode($payload);
  }

  public static function decrypt(string $token): string
  {
    if (substr($token, 0, 3) !== 'NKC') {
      throw new \Exception('Token inválido.');
    }

    $raw = self::base64url_decode(substr($token, 3));
    $key = self::getKey();

    $iv         = substr($raw, 0, 16);
    $mac        = self::bytesParaInt(substr($raw, -4));
    $ciphertext = substr($raw, 16, -4);

    // valida ANTES de decifrar
    $macEsperado = self::checksum($iv . $ciphertext, self::deriveKey($key, 'mac'));
    if (!hash_equals((string)$macEsperado, (string)$mac)) {
      throw new \Exception('Token adulterado ou chave incorreta.');
    }

    return self::xorStream($ciphertext, $key, $iv);
  }

  // ---------------------------------------------------------------
  // NÚCLEO DA CIFRAGEM — tudo caseiro, sem hash()/pack()
  // ---------------------------------------------------------------

  /**
   * Gera o keystream byte a byte e faz XOR com o dado.
   * Cada byte do keystream depende SÓ de key, iv e posição.
   */
  private static function xorStream(string $data, string $key, string $iv): string
  {
    $out = '';
    $len = strlen($data);
    for ($i = 0; $i < $len; $i++) {
      $out .= chr(ord($data[$i]) ^ self::misturar($key, $iv, $i));
    }
    return $out;
  }

  /**
   * Função de mistura: combina key+iv+posição em várias rodadas
   * de operações não-lineares (soma, rotação, XOR, multiplicação).
   */
  private static function misturar(string $key, string $iv, int $posicao): int
  {
    $keyLen = strlen($key);
    $ivLen  = strlen($iv);

    $estado = ord($key[$posicao % $keyLen]) ^ ord($iv[$posicao % $ivLen]);

    for ($rodada = 0; $rodada < 6; $rodada++) {
      $kByte = ord($key[($posicao + $rodada) % $keyLen]);
      $iByte = ord($iv[($posicao + $rodada * 5) % $ivLen]);

      $estado = ($estado + $kByte) & 0xFF;
      $estado = self::rotEsquerda8($estado, 3);
      $estado ^= $iByte;
      $estado = ($estado * 131 + $rodada + $posicao) & 0xFF;
      $estado = self::rotEsquerda8($estado, 5);
    }

    return $estado;
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

  private static function deriveKey(string $key, string $proposito): string
  {
    // deriva uma "subchave" sem usar hash: mistura key com o texto do propósito
    $derivada = '';
    $propLen = strlen($proposito);
    foreach (str_split($key) as $i => $char) {
      $mix = ord($char) ^ ord($proposito[$i % $propLen]) ^ (($i * 37) & 0xFF);
      $derivada .= chr($mix);
    }
    return $derivada;
  }

  // ---------------------------------------------------------------
  // Utilitários de bits e bytes
  // ---------------------------------------------------------------

  private static function rotEsquerda8(int $byte, int $n): int
  {
    $n &= 7;
    return (($byte << $n) | ($byte >> (8 - $n))) & 0xFF;
  }

  private static function rotEsquerda32(int $val, int $n): int
  {
    $n &= 31;
    return (($val << $n) | ($val >> (32 - $n))) & 0xFFFFFFFF;
  }

  private static function intParaBytes(int $val): string
  {
    return chr(($val >> 24) & 0xFF) . chr(($val >> 16) & 0xFF)
      . chr(($val >> 8) & 0xFF) . chr($val & 0xFF);
  }

  private static function bytesParaInt(string $bytes): int
  {
    return (ord($bytes[0]) << 24) | (ord($bytes[1]) << 16)
      | (ord($bytes[2]) << 8) | ord($bytes[3]);
  }

  // ---------------------------------------------------------------

  private static function getKey(): string
  {
    $key = DotEnv::get('IA_CRIPT_KEY_NKC');
    if (strlen($key) !== 32) {
      throw new \Exception('Chave deve ter 32 bytes.');
    }
    return $key;
  }

  private static function base64url_encode(string $data): string
  {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function base64url_decode(string $data): string
  {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
  }
}

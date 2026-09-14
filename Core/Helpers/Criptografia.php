<?php
namespace Application\Core\Helpers;

use Application\Core\Env\DotEnv;
$chave2 = ""; //criada automaticamente
/**
 * Classe de Criptografia
 * @package Application\Core\Helpers
 * @property-read string VERSION
 * @property-read string IA_CRIPT_KEY_NKC
 * @method static string iaCriptNKC(string $text)
 * @method static string iaDecriptNKC(string $text)
 */
class Criptografia
{
  const VERSION = '1.0';
  const IA_CRIPT_KEY_NKC = 'ThisIsA32ByteLongEncryptionKey!';
  /**
   * Encrypts the given text using the provided key.
   *
   * @param string $text The text to encrypt.
   * @param string $key The encryption key.
   * @return string The encrypted text.
   * @throws Exception If the key length is not 32.
   */
  public static function encrypt($text)
  {
    $key = DotEnv::get('IA_CRIPT_KEY_NKC') ?? self::IA_CRIPT_KEY_NKC;
    if (strlen($key) !== 32) {
      throw new \Exception('Invalid key length. Key must be 32 bytes (256 bits).');
    }

    $iv = bin2hex(random_bytes(16));
    mt_srand(hexdec(substr($iv, 0, 8)));
    $ivK = self::xor_encrypt($iv, $key);
    $encrypted = self::xor_encrypt(str_shuffle($text), str_shuffle($iv . $key));

    $cript = self::xor_encrypt(bin2hex($ivK) . '$' . bin2hex($encrypted), $key);
    return 'NKC' . self::base64url_encode($cript);
  }
  /**
   * Decrypts the given text using the provided key.
   *
   * @param string $text The text to decrypt.
   * @param string $key The decryption key.
   * @return string The decrypted text.
   * @throws Exception If the key length is not 32.
   */
  public static function decrypt($text)
  {
    if (substr($text, 0, 3) !== 'NKC') {
        throw new \Exception('Invalid text. Text must start with NKC.');
    }

    $key = DotEnv::get('IA_CRIPT_KEY_NKC') ?? self::IA_CRIPT_KEY_NKC;
    if (strlen($key) !== 32) {
        throw new \Exception('Invalid key length. Key must be 32 bytes (256 bits).');
    }

    $encryptedData = self::xor_encrypt(self::base64url_decode(substr($text, 3)), $key);
    list($ivKHex, $encryptedHex) = explode('$', $encryptedData, 2);

    $iv = self::xor_encrypt(hex2bin($ivKHex), $key);
    $seed = hexdec(substr($iv, 0, 8));

    $encrypted = hex2bin($encryptedHex);
    $len = strlen($encrypted);

    // Reproduz o consumo do str_shuffle($text) feito no encrypt
    mt_srand($seed);
    str_shuffle(str_repeat('x', $len)); // mesmo comprimento => mesmo consumo do PRNG

    $keyShuffled = str_shuffle($iv . $key);

    $shuffledText = self::xor_encrypt($encrypted, $keyShuffled);

    // Volta ao estado inicial para desfazer o shuffle do texto
    mt_srand($seed);
    return self::str_unshuffle($shuffledText);
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
  /**
   * The function decodes a base64url encoded string.
   * @param string $data - The "data" parameter is a string that represents the base64url encoded data that you want to
   * decode.
   * @return string the decoded data after performing base64url decoding.
   */
  public static function base64url_decode($data)
  {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
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

    return $input ^ str_repeat($key, ceil(strlen($input) / strlen($key)));
    // $output = '';
    // for ($i = 0, $len = strlen($input), $keyLen = strlen($key); $i < $len; $i++) {
    //   $output .= chr(ord($input[$i]) ^ ord($key[$i % $keyLen]));
    // }

    // return $output;
  }
  private static function str_unshuffle($str){
    $unique = implode(array_map('chr',range(0,254)));
    $none   = chr(255);
    $slen   = strlen($str);
    $c      = intval(ceil($slen/255));
    $r      = '';
    for($i=0; $i<$c; $i++){
        $aaa = str_repeat($none, $i*255);
        $bbb = (($i+1)<$c) ? $unique : substr($unique, 0, $slen%255);
        $ccc = (($i+1)<$c) ? str_repeat($none, strlen($str)-($i+1)*255) : "";
        $tmp = $aaa.$bbb.$ccc;
        $sh  = str_shuffle($tmp);
        for($j=0; $j<strlen($bbb); $j++){
            $r .= $str[strpos($sh, $unique[$j])];
        }
    }
    return $r;
  }
}

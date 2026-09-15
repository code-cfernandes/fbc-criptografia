import 'dart:typed_data';

/// Campos que compõem um token (já decodificado do base64url).
///
/// As chaves são `integridade`, `ciphertext` e `iv`.
typedef CamposToken = Map<String, Uint8List>;

/// Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.
///
/// Os métodos "obrigatórios" (encrypt/decrypt) bastam pros ataques de alto nível
/// (ida-e-volta, adulteração, colisão de IV, bytes fixos entre tokens).
///
/// `gerarKeystreamBruto` e `checksumBruto` expõem as camadas internas para os
/// ataques de baixo nível (avalanche, distribuição, cobertura de dependência,
/// fold estrutural).
abstract class AlvoCriptografico {
  String encrypt(Object texto);

  String decrypt(String token);

  /// Prefixo esperado no início de um token válido (ex: "FBC").
  String prefixo();

  /// Decompõe um token (sem prefixo e já base64url-decodificado) nos campos.
  CamposToken decompor(Uint8List tokenDecodificado);

  /// Recompõe um token a partir dos campos (inverso de decompor()).
  Uint8List recompor(CamposToken campos);

  /// Gera N bytes de keystream bruto a partir de key+iv+propósito.
  /// Um alvo que não exponha essa camada deve lançar SkipAtaqueException.
  Uint8List gerarKeystreamBruto(
    Object key,
    Object iv,
    String proposito,
    int tamanho,
  );

  /// Chama o checksum() interno diretamente.
  Uint8List checksumBruto(Object dados, Object key);

  /// Uma chave válida pra usar nos testes.
  String chaveDeTeste();

  /// Tamanho do IV em bytes.
  int tamanhoIv();

  String base64urlEncode(Uint8List data);

  Uint8List base64urlDecode(String data);
}

import 'dart:typed_data';

import 'package:criptografia/Core/Criptografia.dart' as core;
import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Util.dart';

const String CHAVE_PADRAO = 'pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf';

/// Liga a suíte de ataques à implementação real de Criptografia, expondo as
/// camadas internas de keystream e checksum.
class CriptografiaAlvo extends AlvoCriptografico {
  final String _chaveTeste;

  CriptografiaAlvo([String chaveTeste = CHAVE_PADRAO])
    : _chaveTeste = chaveTeste {
    core.definirChave(chaveTeste);
  }

  /// Restaura/define a chave global (usado por ataques que trocam a chave).
  static void definirChaveGlobal(String chave) => core.definirChave(chave);

  @override
  String encrypt(Object texto) => core.encrypt(texto);

  @override
  String decrypt(String token) => core.decrypt(token);

  @override
  String prefixo() => 'FBC';

  @override
  CamposToken decompor(Uint8List tokenDecodificado) {
    final buf = toBytes(tokenDecodificado);
    final tamIv = tamanhoIv();
    return {
      'integridade': buf.sublist(0, 32),
      'ciphertext': buf.sublist(32, buf.length - tamIv),
      'iv': buf.sublist(buf.length - tamIv),
    };
  }

  @override
  Uint8List recompor(CamposToken campos) {
    return Uint8List.fromList([
      ...campos['integridade']!,
      ...campos['ciphertext']!,
      ...campos['iv']!,
    ]);
  }

  @override
  Uint8List gerarKeystreamBruto(
    Object key,
    Object iv,
    String proposito,
    int tamanho,
  ) {
    final keyBuf = key is String
        ? Uint8List.fromList(toBytes(key))
        : toBytes(key);
    final ivBuf = toBytes(iv);
    return core.gerarKeystream(keyBuf, ivBuf, proposito, tamanho);
  }

  @override
  Uint8List checksumBruto(Object dados, Object key) {
    return core.checksum(toBytes(dados), toBytes(key));
  }

  @override
  String chaveDeTeste() => _chaveTeste;

  @override
  int tamanhoIv() => 16;

  @override
  Uint8List base64urlDecode(String data) => core.base64urlDecode(data);

  @override
  String base64urlEncode(Uint8List data) => core.base64urlEncode(data);
}

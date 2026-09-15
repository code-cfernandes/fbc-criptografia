import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
/// token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
/// sucesso", a cifra não está autenticando o conteúdo.
class AtaqueAdulteracao extends Ataque {
  final int _tentativas;

  AtaqueAdulteracao({this._tentativas = 500});

  @override
  String nome() => 'Adulteração de bits (integridade)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
    }

    final aceitosIndevidamente = <String>[];

    for (var t = 0; t < _tentativas; t++) {
      final texto = 'MSG_$t${repetir('X', randomInt(0, 50))}';
      final token = alvo.encrypt(texto);
      final decodificado = alvo.base64urlDecode(
        token.substring(alvo.prefixo().length),
      );
      final campos = alvo.decompor(decodificado);

      final nomeCampo = arrayRandKey(campos);
      final valor = Uint8List.fromList(campos[nomeCampo]!);
      if (valor.isEmpty) {
        continue;
      }
      final pos = randomInt(0, valor.length - 1);
      valor[pos] = valor[pos] ^ (1 << randomInt(0, 7));
      campos[nomeCampo] = valor;

      final tokenAdulterado =
          alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(campos));

      try {
        final resultado = alvo.decrypt(tokenAdulterado);
        aceitosIndevidamente.add(
          'campo=$nomeCampo, texto original=$texto, resultado aceito=$resultado',
        );
      } catch (_) {
        // esperado - a adulteração deveria ser rejeitada
      }
    }

    if (aceitosIndevidamente.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        '${aceitosIndevidamente.length} de $_tentativas tokens adulterados '
            'foram ACEITOS',
        {'exemplos': aceitosIndevidamente.take(5).toList()},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todas as $_tentativas adulterações foram rejeitadas',
    );
  }
}

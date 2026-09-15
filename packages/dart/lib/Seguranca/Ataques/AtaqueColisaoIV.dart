import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
/// garantias de confidencialidade (keystream reusado = "two-time pad").
/// Gera muitos tokens do MESMO texto e verifica se os IVs nunca colidem.
class AtaqueColisaoIV extends Ataque {
  final int _geracoes;

  AtaqueColisaoIV({this._geracoes = 5000});

  @override
  String nome() => 'Colisão de IV';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    final vistos = <String>{};
    var colisoes = 0;

    for (var i = 0; i < _geracoes; i++) {
      final token = alvo.encrypt('MESMO_TEXTO_SEMPRE');
      final decodificado = alvo.base64urlDecode(
        token.substring(alvo.prefixo().length),
      );
      final iv = alvo.decompor(decodificado)['iv']!;
      final chaveIv = bytesToHex(iv);
      if (!vistos.add(chaveIv)) {
        colisoes++;
      }
    }

    if (colisoes > 0) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        '$colisoes colisão(ões) de IV em $_geracoes gerações',
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      '0 colisões em $_geracoes gerações',
    );
  }
}

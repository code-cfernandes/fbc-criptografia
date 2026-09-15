import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';

/// Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
/// (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
/// Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
class AtaqueMac extends Ataque {
  final String _mensagem;

  AtaqueMac({this._mensagem = 'mensagem para o ataque de MAC'});

  @override
  String nome() => 'Força bruta e truncamento do MAC';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final token = alvo.encrypt(_mensagem);
    final decoded = alvo.base64urlDecode(token.substring(alvo.prefixo().length));
    final campos = alvo.decompor(decoded);

    final integridade = campos['integridade']!;
    final ciphertext = campos['ciphertext']!;
    final iv = campos['iv']!;

    String montar(Uint8List integ) => alvo.prefixo() +
        alvo.base64urlEncode(
          alvo.recompor({
            'integridade': integ,
            'ciphertext': ciphertext,
            'iv': iv,
          }),
        );

    final aceitos = <String>[];

    // 1) integridade zerada
    try {
      alvo.decrypt(montar(Uint8List(integridade.length)));
      aceitos.add('integridade zerada');
    } catch (_) {
      // esperado
    }

    // 2) integridade truncada pela metade
    try {
      alvo.decrypt(montar(integridade.sublist(0, 16)));
      aceitos.add('integridade truncada (16 bytes)');
    } catch (_) {
      // esperado
    }

    // 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
    // que reconstruiria o próprio token válido e não é uma forja)
    final base = Uint8List.fromList(integridade);
    for (var v = 0; v < 256; v++) {
      if (v == base[0]) continue;
      final tentativa = Uint8List.fromList(base);
      tentativa[0] = v;
      try {
        alvo.decrypt(montar(tentativa));
        aceitos.add('byte 0 do MAC = $v');
      } catch (_) {
        // esperado
      }
    }

    final vulneravel = aceitos.isNotEmpty;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      vulneravel
          ? '${aceitos.length} variante(s) de MAC aceitas: '
                '${aceitos.take(5).join('; ')}'
          : 'Nenhuma das 257 variantes (zerada, truncada, 255 bytes '
                'forçados) foi aceita',
      {'aceitos': aceitos},
    );
  }
}

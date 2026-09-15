import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';

/// Length extension / truncamento: a estrutura do token é
/// integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
/// Truncar, estender ou deslocar bytes não pode produzir um token aceito.
class AtaqueLengthExtension extends Ataque {
  final String _mensagem;

  AtaqueLengthExtension({
    String mensagem = 'texto para o ataque de length extension',
  }) : _mensagem = mensagem;

  @override
  String nome() => 'Length extension / truncamento de token';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final prefixo = alvo.prefixo();
    final token = alvo.encrypt(_mensagem);
    final corpo = token.substring(prefixo.length);
    final meio = corpo.length ~/ 2;

    final variantes = <String, String>{
      'append A': '${prefixo}$corpo' 'A',
      'append =': '${prefixo}$corpo' '=',
      'truncar 1 char': prefixo + corpo.substring(0, corpo.length - 1),
      'truncar 2 chars': prefixo + corpo.substring(0, corpo.length - 2),
      'inserir ! no meio':
          prefixo + corpo.substring(0, meio) + '!' + corpo.substring(meio),
      'prefixo extra': '${prefixo}A$corpo',
    };

    // variantes que mexem nos campos decodificados
    try {
      final decoded = alvo.base64urlDecode(corpo);
      final campos = alvo.decompor(decoded);
      final integridade = campos['integridade']!;
      final ciphertext = campos['ciphertext']!;
      final iv = campos['iv']!;

      final ctMaior = Uint8List.fromList([...ciphertext, 0x41]);
      variantes['ciphertext +1 byte'] = prefixo +
          alvo.base64urlEncode(
            alvo.recompor({
              'integridade': integridade,
              'ciphertext': ctMaior,
              'iv': iv,
            }),
          );

      final ctMenor = Uint8List.fromList(
        ciphertext.sublist(0, max(0, ciphertext.length - 1)),
      );
      variantes['ciphertext -1 byte'] = prefixo +
          alvo.base64urlEncode(
            alvo.recompor({
              'integridade': integridade,
              'ciphertext': ctMenor,
              'iv': iv,
            }),
          );

      final ivMaior = Uint8List.fromList([...iv, 0x42]);
      variantes['iv +1 byte'] = prefixo +
          alvo.base64urlEncode(
            alvo.recompor({
              'integridade': integridade,
              'ciphertext': ciphertext,
              'iv': ivMaior,
            }),
          );
    } catch (_) {
      // se a decodificação falhar, segue com as variantes textuais
    }

    final aceitas = <String>[];
    for (final entry in variantes.entries) {
      if (entry.value == token) continue;
      try {
        alvo.decrypt(entry.value);
        aceitas.add(entry.key);
      } catch (_) {
        // esperado
      }
    }

    final vulneravel = aceitas.isNotEmpty;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      vulneravel
          ? '${aceitas.length} variante(s) aceita(s): ${aceitas.join('; ')}'
          : 'Todas as ${variantes.length} variantes de truncamento/extensão '
                'foram rejeitadas',
      {'aceitas': aceitas},
    );
  }
}

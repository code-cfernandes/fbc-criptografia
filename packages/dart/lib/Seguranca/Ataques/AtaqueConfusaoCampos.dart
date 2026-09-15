import 'dart:convert';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
/// ambíguo, um atacante pode reordenar/deslocar os campos e construir um
/// token que sistemas diferentes interpretam de formas diferentes. Todos os
/// rearranjos devem ser rejeitados pela integridade.
class AtaqueConfusaoCampos extends Ataque {
  @override
  String nome() =>
      'Confusão de campos do token (reordenação/deslocamento)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException(
        'Precisa de base64url_encode/decode do alvo.',
      );
    }

    const texto = 'MENSAGEM_PARA_TESTE_DE_CAMPOS';
    final token = alvo.encrypt(texto);
    final prefixo = alvo.prefixo();
    final campos = alvo.decompor(
      alvo.base64urlDecode(token.substring(prefixo.length)),
    );

    final integridade = campos['integridade']!;
    final ciphertext = campos['ciphertext']!;
    final iv = campos['iv']!;

    Uint8List juntar(List<List<int>> partes) =>
        Uint8List.fromList(partes.expand((p) => p).toList());

    final variantes = <String, Uint8List>{
      'iv no início': juntar([iv, integridade, ciphertext]),
      'ciphertext antes da integridade':
          juntar([ciphertext, integridade, iv]),
      'iv duplicado no fim': juntar([integridade, ciphertext, iv, iv]),
      'integridade encurtada':
          juntar([integridade.sublist(1), ciphertext, iv]),
      'byte extra no início':
          juntar([toBytes('X'), integridade, ciphertext, iv]),
      'byte extra entre integridade e ciphertext':
          juntar([integridade, toBytes('X'), ciphertext, iv]),
      'byte extra antes do iv':
          juntar([integridade, ciphertext, toBytes('X'), iv]),
      'iv rotacionado': juntar([
        integridade,
        ciphertext,
        iv.reversed.toList(),
      ]),
      'iv e último byte do ciphertext trocados': juntar([
        integridade,
        ciphertext.sublist(0, ciphertext.length - 1),
        iv,
        ciphertext.sublist(ciphertext.length - 1),
      ]),
    };

    final aceitas = <String>[];
    for (final entry in variantes.entries) {
      final bruto = entry.value;
      final tokenVariante = prefixo + alvo.base64urlEncode(bruto);
      try {
        final r = alvo.decrypt(tokenVariante);
        aceitas.add(
          '${entry.key} -> aceito (retornou ${utf8.encode(r).length} bytes)',
        );
      } catch (_) {
        // esperado
      }
    }

    if (aceitas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        '${aceitas.length} rearranjo(s) de campo foram aceitos',
        {'exemplos': aceitas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todos os ${variantes.length} rearranjos de campo foram rejeitados',
    );
  }
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
/// verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
/// vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
/// truncation) só aparecem com bytes arbitrários.
///
/// Adaptação Dart: os dados são bytes; como decrypt() devolve string
/// (UTF-8, com bytes inválidos virando U+FFFD), comparamos com a representação
/// UTF-8 leniente dos mesmos bytes.
class AtaqueIdaEVoltaBinario extends Ataque {
  final int _tamanhoMaximo;

  AtaqueIdaEVoltaBinario({this._tamanhoMaximo = 256});

  @override
  String nome() => 'Ida-e-volta com dados binários (inclui NUL)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final falhas = <String>[];

    for (var len = 0; len <= _tamanhoMaximo; len++) {
      final texto = len == 0 ? Uint8List(0) : randomBytes(len);
      try {
        if (alvo.decrypt(alvo.encrypt(texto)) !=
            utf8.decode(texto, allowMalformed: true)) {
          falhas.add('$len');
        }
      } catch (e) {
        falhas.add('$len (erro: $e)');
      }
    }

    final todos = Uint8List.fromList(List<int>.generate(256, (i) => i));
    if (alvo.decrypt(alvo.encrypt(todos)) !=
        utf8.decode(todos, allowMalformed: true)) {
      falhas.add('todos os 256 valores de byte');
    }

    if (falhas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        'Falhou em ${falhas.length} caso(s): ${falhas.take(10).join(', ')}',
        {'falhas': falhas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todos os tamanhos 0..$_tamanhoMaximo e os 256 valores de byte '
          'preservados',
    );
  }
}

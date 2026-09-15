import 'dart:convert';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
/// sincronização de bloco, repetição de keystream em blocos distantes ou
/// perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
/// curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
/// gera tokens diferentes.
///
/// Adaptação Dart: os dados são bytes; como decrypt() devolve string
/// (UTF-8 leniente), comparamos com a representação UTF-8 dos mesmos bytes.
class AtaqueMensagemLonga extends Ataque {
  final List<int> _tamanhos;

  AtaqueMensagemLonga({List<int> tamanhos = const [1000, 10000, 100000]})
    : _tamanhos = tamanhos;

  @override
  String nome() => 'Mensagens longas (multi-bloco)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final falhas = <String>[];

    for (final t in _tamanhos) {
      final texto = randomBytes(t);
      try {
        final token = alvo.encrypt(texto);
        if (alvo.decrypt(token) != utf8.decode(texto, allowMalformed: true)) {
          falhas.add('$t bytes (conteúdo diferente)');
        }
      } catch (e) {
        falhas.add('$t bytes (erro: $e)');
      }
    }

    final texto = repetir('A', 1000);
    final t1 = alvo.encrypt(texto);
    final t2 = alvo.encrypt(texto);
    if (t1 == t2) {
      falhas.add('tokens idênticos para o mesmo texto (IV não varia)');
    }

    if (falhas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        'Falha em: ${falhas.join('; ')}',
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Ida-e-volta OK em ${_tamanhos.join(', ')} bytes; '
          'mesmo texto gera tokens distintos',
    );
  }
}

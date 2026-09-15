import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
/// Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
/// autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
/// estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
/// keystream aleatório deve ter todos esses indicadores perto de zero/50%.
class AtaqueAutocorrelacao extends Ataque {
  final int _tamanho;
  final int _tamanhoBloco;

  AtaqueAutocorrelacao({int tamanho = 8192, int tamanhoBloco = 32})
    : _tamanho = tamanho,
      _tamanhoBloco = tamanhoBloco;

  @override
  String nome() => 'Autocorrelação e periodicidade do keystream';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      _tamanho,
    );

    final serial = _correlacao(ks, 1);

    final suspeitos = <int, double>{};
    for (final lag in [2, 4, 8, 16, 32, 64, 128, 256]) {
      final c = _correlacao(ks, lag);
      if (c.abs() > 0.1) {
        suspeitos[lag] = c;
      }
    }

    final blocos = <Uint8List>[];
    for (var i = 0; i < ks.length; i += _tamanhoBloco) {
      blocos.add(ks.sublist(i, min(i + _tamanhoBloco, ks.length)));
    }
    final blocosUnicos = blocos.map(bytesToHex).toSet();
    final blocosRepetidos = blocos.length - blocosUnicos.length;

    final uns = contarBitsBuffer(ks);
    final fracaoUns = uns / (ks.length * 8);

    final problemas = <String>[];
    if (serial.abs() > 0.1) {
      problemas.add('correlação serial=${serial.toStringAsFixed(3)}');
    }
    if (suspeitos.isNotEmpty) {
      problemas.add(
        'autocorrelação em lag(s) ${suspeitos.keys.join(', ')}',
      );
    }
    if (blocosRepetidos > 0) {
      problemas.add(
        '$blocosRepetidos bloco(s) de $_tamanhoBloco bytes repetido(s)',
      );
    }
    if (fracaoUns < 0.45 || fracaoUns > 0.55) {
      problemas.add(
        'balanço de bits=${(fracaoUns * 100).toStringAsFixed(1)}% de 1s',
      );
    }

    if (problemas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.media,
        problemas.join('; '),
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'serial=${serial.toStringAsFixed(3)}, nenhum lag com correlação >10%, '
          '0 blocos repetidos em ${blocos.length}, '
          '${(fracaoUns * 100).toStringAsFixed(1)}% de bits 1',
    );
  }

  double _correlacao(Uint8List s, int lag) {
    final n = s.length;
    if (n <= lag) {
      return 0.0;
    }

    var soma = 0;
    for (var i = 0; i < n; i++) {
      soma += s[i];
    }
    final media = soma / n;

    var num = 0.0;
    var den = 0.0;
    for (var i = 0; i < n; i++) {
      den += pow(s[i] - media, 2).toDouble();
    }
    for (var i = 0; i < n - lag; i++) {
      num += (s[i] - media) * (s[i + lag] - media);
    }

    return den > 0 ? num / den : 0.0;
  }
}

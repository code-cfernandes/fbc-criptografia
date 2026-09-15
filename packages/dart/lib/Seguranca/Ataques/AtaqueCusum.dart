import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
/// passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
/// pequeno que o monobit quase não vê faz o desvio acumulado crescer.
/// Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
class AtaqueCusum extends Ataque {
  final int _tamanho;
  final double _limiteZ;

  AtaqueCusum({int tamanho = 8192, double limiteZ = 4.0})
    : _tamanho = tamanho,
      _limiteZ = limiteZ;

  @override
  String nome() => 'Somas cumulativas (cusum)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      _tamanho,
    );

    var soma = 0;
    var maxAbs = 0;
    for (var i = 0; i < ks.length; i++) {
      final byte = ks[i];
      for (var b = 7; b >= 0; b--) {
        soma += ((byte >> b) & 1) == 1 ? 1 : -1;
        maxAbs = max(maxAbs, soma.abs());
      }
    }
    final n = ks.length * 8;
    final z = maxAbs / sqrt(n);
    final vulneravel = z > _limiteZ;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      'max|S|=$maxAbs sobre $n bits, '
          'max|S|/sqrt(n)=${z.toStringAsFixed(2)} '
          '(limite=${_limiteZ.toStringAsFixed(1)})',
      {'max_abs': maxAbs, 'z': z},
    );
  }
}

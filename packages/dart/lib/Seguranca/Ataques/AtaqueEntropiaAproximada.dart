import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
/// previsibilidade local: para uma sequência aleatória, a chance de repetir um
/// bloco de m bits deve cair suavemente conforme m cresce. Estruturas
/// periódicas/recorrentes produzem ApEn anômala.
///
/// O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
/// um valor esperado teórico. Comparamos o keystream com um CONTROLE de
/// random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
/// estatisticamente indistinguíveis.
class AtaqueEntropiaAproximada extends Ataque {
  final int _tamanho;
  final int _m;
  final int _controles;
  final int _amostrasKeystream;
  final double _limiteZ;

  AtaqueEntropiaAproximada({
    int tamanho = 4096,
    int m = 8,
    int controles = 12,
    int amostrasKeystream = 3,
    double limiteZ = 5.0,
  }) : _tamanho = tamanho,
       _m = m,
       _controles = controles,
       _amostrasKeystream = amostrasKeystream,
       _limiteZ = limiteZ;

  @override
  String nome() => 'Entropia aproximada (ApEn vs controle aleatório)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chiControle = <double>[];
    for (var c = 0; c < _controles; c++) {
      chiControle.add(_estatistico(randomBytes(_tamanho)));
    }
    final mediaControle =
        chiControle.reduce((a, b) => a + b) / chiControle.length;
    var variancia = 0.0;
    for (final v in chiControle) {
      variancia += pow(v - mediaControle, 2).toDouble();
    }
    final desvioControle =
        sqrt(variancia / max(1, chiControle.length - 1));

    final chiKeystream = <double>[];
    for (var k = 0; k < _amostrasKeystream; k++) {
      final ks = alvo.gerarKeystreamBruto(
        alvo.chaveDeTeste(),
        randomBytes(alvo.tamanhoIv()),
        'enc',
        _tamanho,
      );
      chiKeystream.add(_estatistico(ks));
    }
    final mediaKeystream =
        chiKeystream.reduce((a, b) => a + b) / chiKeystream.length;

    final z = desvioControle > 0
        ? (mediaKeystream - mediaControle) / desvioControle
        : 0.0;
    final vulneravel = z.abs() > _limiteZ;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      'chi2 keystream=${mediaKeystream.toStringAsFixed(1)}, '
          'controle=${mediaControle.toStringAsFixed(1)} '
          '(sd=${desvioControle.toStringAsFixed(1)}), '
          'z=${z.toStringAsFixed(2)} '
          '(limite=${_limiteZ.toStringAsFixed(1)})',
      {
        'chi_keystream': mediaKeystream,
        'chi_controle': mediaControle,
        'z': z,
      },
    );
  }

  /// chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1).
  double _estatistico(List<int> bytes) {
    final bits = _paraBits(bytes);
    final n = bits.length;
    final apen = _phi(bits, _m, n) - _phi(bits, _m + 1, n);
    return 2 * n * (log(2) - apen);
  }

  double _phi(List<int> bits, int m, int n) {
    final total = 1 << m;
    final contagem = List<int>.filled(total, 0);
    final janelas = n - m + 1;

    for (var i = 0; i < janelas; i++) {
      var v = 0;
      for (var j = 0; j < m; j++) {
        v = (v << 1) | bits[i + j];
      }
      contagem[v]++;
    }

    var soma = 0.0;
    for (final c in contagem) {
      if (c > 0) {
        final p = c / janelas;
        soma += p * log(p);
      }
    }

    return soma;
  }

  List<int> _paraBits(List<int> bytes) {
    final bits = <int>[];
    for (var i = 0; i < bytes.length; i++) {
      final byte = bytes[i];
      for (var b = 7; b >= 0; b--) {
        bits.add((byte >> b) & 1);
      }
    }
    return bits;
  }
}

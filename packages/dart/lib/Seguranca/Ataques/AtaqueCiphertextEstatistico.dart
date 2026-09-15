import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
/// (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
/// de cifra sólida deve parecer ruído mesmo com plaintext variado.
class AtaqueCiphertextEstatistico extends Ataque {
  final int _amostras;
  final int _tamanhoTexto;
  final double _zLimite;

  AtaqueCiphertextEstatistico({
    this._amostras = 200,
    this._tamanhoTexto = 64,
    this._zLimite = 4,
  });

  @override
  String nome() => 'Estatística do ciphertext (chi²/runs/autocorrelação)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final contagem = List<int>.filled(256, 0);
    final bytes = <int>[];

    for (var s = 0; s < _amostras; s++) {
      final texto = randomBytes(_tamanhoTexto);
      final token = alvo.encrypt(texto);
      final campos = alvo.decompor(
        alvo.base64urlDecode(token.substring(alvo.prefixo().length)),
      );
      for (final b in campos['ciphertext']!) {
        contagem[b]++;
        bytes.add(b);
      }
    }

    final total = bytes.length;
    final esperado = total / 256;
    var chi2 = 0.0;
    for (var b = 0; b < 256; b++) {
      final d = contagem[b] - esperado;
      chi2 += (d * d) / esperado;
    }

    // runs test nos bits do ciphertext
    var uns = 0;
    final bits = <int>[];
    for (final b in bytes) {
      for (var k = 7; k >= 0; k--) {
        final bit = (b >> k) & 1;
        bits.add(bit);
        uns += bit;
      }
    }
    final n = bits.length;
    final pi = uns / n;
    var runs = 1;
    for (var i = 1; i < n; i++) {
      if (bits[i] != bits[i - 1]) runs++;
    }
    final esperadoRuns = 2 * n * pi * (1 - pi);
    final desvioRuns = 2 * sqrt(2 * n) * pi * (1 - pi);
    final zRuns = desvioRuns > 0
        ? (runs - esperadoRuns).abs() / desvioRuns
        : 0.0;

    // autocorrelação lag-1
    final media = bytes.reduce((a, b) => a + b) / total;
    var num = 0.0;
    var den = 0.0;
    for (var i = 0; i < total; i++) {
      den += pow(bytes[i] - media, 2).toDouble();
    }
    for (var i = 0; i < total - 1; i++) {
      num += (bytes[i] - media) * (bytes[i + 1] - media);
    }
    final autocorr = den > 0 ? num / den : 0.0;

    final problemas = <String>[];
    if (chi2 > 330) {
      problemas.add('qui-quadrado=${chi2.toStringAsFixed(1)} (>330 suspeito)');
    }
    if (zRuns > _zLimite) {
      problemas.add('runs z=${zRuns.toStringAsFixed(2)}');
    }
    if (autocorr.abs() > 0.1) {
      problemas.add('autocorrelação=${autocorr.toStringAsFixed(3)}');
    }

    final vulneravel = problemas.isNotEmpty;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      vulneravel
          ? problemas.join('; ')
          : 'qui-quadrado=${chi2.toStringAsFixed(1)} sobre $total bytes, '
                'runs z=${zRuns.toStringAsFixed(2)}, '
                'autocorrelação=${autocorr.toStringAsFixed(3)} - todos '
                'dentro do esperado',
      {'chi2': chi2, 'runs_z': zRuns, 'autocorrelacao': autocorr},
    );
  }
}

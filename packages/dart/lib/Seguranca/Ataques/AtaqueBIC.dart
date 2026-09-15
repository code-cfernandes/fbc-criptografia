import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// BIC (Bit Independence Criterion): pares de bits de saída não devem estar
/// correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
/// e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
/// cada par de bits de saída. Pares muito correlacionados indicam difusão
/// acoplada (um bit "carrega" informação sobre outro).
class AtaqueBIC extends Ataque {
  final int _tamanhoBloco;
  final int _amostras;
  final double _limite;

  AtaqueBIC({
    this._tamanhoBloco = 32,
    this._amostras = 300,
    this._limite = 0.35,
  });

  @override
  String nome() => 'BIC (Bit Independence Criterion)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = toBytes(alvo.chaveDeTeste());
    final totalBits = _tamanhoBloco * 8;
    final tamanhoIv = alvo.tamanhoIv();

    final amostrasFlips = <List<int>>[];
    for (var s = 0; s < _amostras; s++) {
      final iv1 = randomBytes(tamanhoIv);
      final iv2 = Uint8List.fromList(iv1);
      final pos = randomInt(0, tamanhoIv - 1);
      iv2[pos] ^= 1 << randomInt(0, 7);

      final ks1 = alvo.gerarKeystreamBruto(
        chave,
        iv1,
        'enc',
        _tamanhoBloco,
      );
      final ks2 = alvo.gerarKeystreamBruto(
        chave,
        iv2,
        'enc',
        _tamanhoBloco,
      );

      final flips = List<int>.filled(totalBits, 0);
      for (var j = 0; j < totalBits; j++) {
        final b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
        final b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
        flips[j] = b1 != b2 ? 1 : 0;
      }
      amostrasFlips.add(flips);
    }

    var piorPhi = 0.0;
    var piorParA = -1;
    var piorParB = -1;
    final n = _amostras;

    for (var a = 0; a < totalBits; a++) {
      for (var b = a + 1; b < totalBits; b++) {
        var n11 = 0;
        var n10 = 0;
        var n01 = 0;
        var n00 = 0;
        for (var s = 0; s < n; s++) {
          final fa = amostrasFlips[s][a];
          final fb = amostrasFlips[s][b];
          if (fa == 1 && fb == 1) {
            n11++;
          } else if (fa == 1 && fb == 0) {
            n10++;
          } else if (fa == 0 && fb == 1) {
            n01++;
          } else {
            n00++;
          }
        }
        final den = sqrt(
          (n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00),
        );
        final phi = den > 0 ? (n11 * n00 - n10 * n01) / den : 0.0;
        if (phi.abs() > piorPhi.abs()) {
          piorPhi = phi;
          piorParA = a;
          piorParB = b;
        }
      }
    }

    final vulneravel = piorPhi.abs() > _limite;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'maior |phi|=${piorPhi.abs().toStringAsFixed(3)} entre bits de saída '
          '[$piorParA, $piorParB] (limite $_limite); $n amostras',
      {'pior_phi': piorPhi, 'par': [piorParA, piorParB]},
    );
  }
}

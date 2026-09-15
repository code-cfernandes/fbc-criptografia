import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
/// esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
/// bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
class AtaqueSAC extends Ataque {
  final int _tamanhoBloco;
  final int _amostras;
  final double _tolerancia;

  AtaqueSAC({
    int tamanhoBloco = 32,
    int amostras = 40,
    double tolerancia = 0.05,
  }) : _tamanhoBloco = tamanhoBloco,
       _amostras = amostras,
       _tolerancia = tolerancia;

  @override
  String nome() => 'SAC (Strict Avalanche Criterion)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = toBytes(alvo.chaveDeTeste());
    final totalBits = _tamanhoBloco * 8;
    final flips = List<int>.filled(totalBits, 0);
    final tamanhoIv = alvo.tamanhoIv();
    var total = 0;

    for (var pos = 0; pos < tamanhoIv; pos++) {
      for (var bit = 0; bit < 8; bit++) {
        for (var s = 0; s < _amostras; s++) {
          final iv1 = randomBytes(tamanhoIv);
          final iv2 = Uint8List.fromList(iv1);
          iv2[pos] ^= 1 << bit;

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

          for (var j = 0; j < totalBits; j++) {
            final b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
            final b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
            if (b1 != b2) {
              flips[j]++;
            }
          }
          total++;
        }
      }
    }

    var pior = -1;
    var piorDesvio = 0.0;
    var piorP = 0.5;
    for (var j = 0; j < totalBits; j++) {
      final p = flips[j] / total;
      final desvio = (p - 0.5).abs();
      if (desvio > piorDesvio) {
        piorDesvio = desvio;
        pior = j;
        piorP = p;
      }
    }

    final vulneravel = piorDesvio > _tolerancia;
    final detalhes =
        'pior bit de saída=$pior: p=${(piorP * 100).toStringAsFixed(2)}% '
        '(esperado 50%, tolerância ±'
        '${(_tolerancia * 100).toStringAsFixed(1)}%); '
        '$total amostras por bit de entrada';

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      detalhes,
      {'pior': pior, 'pior_p': piorP, 'desvio': piorDesvio},
    );
  }
}

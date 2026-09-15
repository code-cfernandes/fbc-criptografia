import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Aproximação linear (criptoanálise de Matsui): procura por correlação entre
/// bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
/// aproximação linear com viés relevante; bias alto é uma pista explorável.
class AtaqueAproximacaoLinear extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;
  final double _limiteBias;

  AtaqueAproximacaoLinear({
    this._amostras = 200,
    this._tamanhoBloco = 32,
    this._limiteBias = 0.3,
  });

  @override
  String nome() => 'Aproximação linear (viés de Walsh)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tamIv = alvo.tamanhoIv();
    final bitsEntrada = tamIv * 8;
    final bitsSaida = _tamanhoBloco * 8;

    final entradas = <Uint8List>[];
    final saidas = <Uint8List>[];

    for (var s = 0; s < _amostras; s++) {
      final chave = randomBytes(toBytes(alvo.chaveDeTeste()).length);
      final iv = randomBytes(tamIv);
      final ks = alvo.gerarKeystreamBruto(
        chave,
        iv,
        'enc',
        _tamanhoBloco,
      );

      final inBits = Uint8List(bitsEntrada);
      for (var j = 0; j < bitsEntrada; j++) {
        inBits[j] = (iv[j >> 3] >> (7 - (j & 7))) & 1;
      }
      final outBits = Uint8List(bitsSaida);
      for (var j = 0; j < bitsSaida; j++) {
        outBits[j] = (ks[j >> 3] >> (7 - (j & 7))) & 1;
      }
      entradas.add(inBits);
      saidas.add(outBits);
    }

    var maiorBias = 0.0;
    var parI = -1;
    var parJ = -1;
    for (var i = 0; i < bitsEntrada; i++) {
      for (var j = 0; j < bitsSaida; j++) {
        var iguais = 0;
        for (var s = 0; s < _amostras; s++) {
          if (entradas[s][i] == saidas[s][j]) {
            iguais++;
          }
        }
        final bias = (iguais / _amostras - 0.5).abs();
        if (bias > maiorBias) {
          maiorBias = bias;
          parI = i;
          parJ = j;
        }
      }
    }

    final vulneravel = maiorBias > _limiteBias;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'maior viés |p-0.5|=${maiorBias.toStringAsFixed(4)} na aproximação '
          'IV[bit $parI] -> saída[bit $parJ] (limite $_limiteBias); '
          '$_amostras amostras',
      {'maior_bias': maiorBias, 'par': [parI, parJ]},
    );
  }
}

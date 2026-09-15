import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
/// 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
/// de byte saem com mais frequência que outros - sinal de fraqueza estatística
/// na função de mistura.
class AtaqueDistribuicaoBytes extends Ataque {
  final int _amostrasDeBlocos;
  final int _tamanhoBloco;

  AtaqueDistribuicaoBytes({
    this._amostrasDeBlocos = 500,
    this._tamanhoBloco = 32,
  });

  @override
  String nome() => 'Distribuição de bytes (qui-quadrado)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();

    final contagem = List<int>.filled(256, 0);
    var total = 0;
    for (var i = 0; i < _amostrasDeBlocos; i++) {
      final ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        _tamanhoBloco,
      );
      for (var j = 0; j < ks.length; j++) {
        contagem[ks[j]]++;
        total++;
      }
    }

    final esperado = total / 256;
    var qui2 = 0.0;
    for (final c in contagem) {
      qui2 += pow(c - esperado, 2).toDouble() / esperado;
    }

    // Com 255 graus de liberdade, valores acima de ~330 já são
    // estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
    final vulneravel = qui2 > 330;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      'qui-quadrado=${qui2.toStringAsFixed(1)} sobre $total bytes '
          '(255 graus de liberdade; >330 é suspeito)',
      {'qui2': qui2},
    );
  }
}

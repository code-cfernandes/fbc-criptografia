import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
/// bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
/// soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
class AtaqueDistribuicaoPorPosicao extends Ataque {
  final int _amostrasDeBlocos;
  final int _tamanhoBloco;

  AtaqueDistribuicaoPorPosicao({
    this._amostrasDeBlocos = 2000,
    this._tamanhoBloco = 32,
  });

  @override
  String nome() => 'Distribuição de bytes por posição do bloco';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();

    final contagens = <List<int>>[];
    for (var p = 0; p < _tamanhoBloco; p++) {
      contagens.add(List<int>.filled(256, 0));
    }

    for (var i = 0; i < _amostrasDeBlocos; i++) {
      final ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        _tamanhoBloco,
      );
      for (var p = 0; p < _tamanhoBloco; p++) {
        contagens[p][ks[p]]++;
      }
    }

    final esperado = _amostrasDeBlocos / 256;
    final problemas = <String>[];
    var pior = 0.0;

    for (var p = 0; p < contagens.length; p++) {
      final c = contagens[p];
      var chi2 = 0.0;
      for (final v in c) {
        chi2 += pow(v - esperado, 2).toDouble() / esperado;
      }
      pior = max(pior, chi2);
      final z = (chi2 - 255) / sqrt(510);
      if (z > 4.0) {
        problemas.add('posição $p chi2=${chi2.toStringAsFixed(1)}');
      }
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
      'Todas as $_tamanhoBloco posições uniformes '
          '(pior chi2=${pior.toStringAsFixed(1)}, esperado ~255)',
    );
  }
}

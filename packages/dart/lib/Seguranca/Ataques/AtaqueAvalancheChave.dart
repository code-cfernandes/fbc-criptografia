import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
/// CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
/// inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
/// Números baixos indicam que parte da chave tem pouca influência - o que
/// reduziria o espaço de busca de um atacante.
class AtaqueAvalancheChave extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;
  final double _limiteMedia;
  final double _limitePiorCaso;

  AtaqueAvalancheChave({
    int amostras = 3000,
    int tamanhoBloco = 32,
    double limiteMedia = 0.45,
    double limitePiorCaso = 0.3,
  }) : _amostras = amostras,
       _tamanhoBloco = tamanhoBloco,
       _limiteMedia = limiteMedia,
       _limitePiorCaso = limitePiorCaso;

  @override
  String nome() => 'Efeito avalanche da chave';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chaveBase = toBytes(alvo.chaveDeTeste());
    final lenChave = chaveBase.length;
    final iv = randomBytes(alvo.tamanhoIv());

    final valores = <double>[];
    for (var t = 0; t < _amostras; t++) {
      final chave = Uint8List.fromList(chaveBase);
      final pos = randomInt(0, lenChave - 1);
      chave[pos] = chave[pos] ^ (1 << randomInt(0, 7));

      final ks1 = alvo.gerarKeystreamBruto(
        chaveBase,
        iv,
        'enc',
        _tamanhoBloco,
      );
      final ks2 = alvo.gerarKeystreamBruto(
        chave,
        iv,
        'enc',
        _tamanhoBloco,
      );

      valores.add(bitsDiferentes(ks1, ks2) / (_tamanhoBloco * 8));
    }

    valores.sort();
    final n = valores.length;
    final media = valores.reduce((a, b) => a + b) / n;
    final piorCaso = valores[0];

    final vulneravel =
        media < _limiteMedia || piorCaso < _limitePiorCaso;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'média=${(media * 100).toStringAsFixed(1)}%, '
          'pior caso=${(piorCaso * 100).toStringAsFixed(1)}% '
          '(limites: média>=${(_limiteMedia * 100).toStringAsFixed(0)}%, '
          'pior>=${(_limitePiorCaso * 100).toStringAsFixed(0)}%)',
      {'media': media, 'pior_caso': piorCaso},
    );
  }
}

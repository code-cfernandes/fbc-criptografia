import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
/// 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
/// schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
/// estrutura (distância de Hamming baixa).
class AtaqueChaveRelacionada extends Ataque {
  final int _tamanhoBloco;
  final int _ivPorDelta;
  final double _limiteMedia;
  final double _limitePior;

  AtaqueChaveRelacionada({
    int tamanhoBloco = 32,
    int ivPorDelta = 3,
    double limiteMedia = 0.45,
    double limitePior = 0.3,
  }) : _tamanhoBloco = tamanhoBloco,
       _ivPorDelta = ivPorDelta,
       _limiteMedia = limiteMedia,
       _limitePior = limitePior;

  @override
  String nome() => 'Chave relacionada (related-key)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chaveBase = toBytes(alvo.chaveDeTeste());
    final len = chaveBase.length;

    final deltas = <Uint8List>[];
    for (var i = 0; i < len; i++) {
      final d = Uint8List(len);
      d[i] = 0x01;
      deltas.add(d);
    }
    for (var i = 0; i < len; i++) {
      final d = Uint8List(len);
      d[i] = 0xff;
      deltas.add(d);
    }
    final complemento = Uint8List.fromList(
      chaveBase.map((b) => b ^ 0xff).toList(),
    );
    deltas.add(complemento);

    final valores = <double>[];
    final totalBits = _tamanhoBloco * 8;

    for (final delta in deltas) {
      final chaveRelacionada = Uint8List.fromList(chaveBase);
      for (var i = 0; i < len; i++) {
        chaveRelacionada[i] ^= delta[i];
      }
      for (var s = 0; s < _ivPorDelta; s++) {
        final iv = randomBytes(alvo.tamanhoIv());
        final ks1 = alvo.gerarKeystreamBruto(
          chaveBase,
          iv,
          'enc',
          _tamanhoBloco,
        );
        final ks2 = alvo.gerarKeystreamBruto(
          chaveRelacionada,
          iv,
          'enc',
          _tamanhoBloco,
        );
        valores.add(bitsDiferentes(ks1, ks2) / totalBits);
      }
    }

    final media = valores.reduce((a, b) => a + b) / valores.length;
    var pior = valores[0];
    for (final v in valores) {
      if (v < pior) pior = v;
    }
    final vulneravel = media < _limiteMedia || pior < _limitePior;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'média=${(media * 100).toStringAsFixed(1)}%, '
          'pior=${(pior * 100).toStringAsFixed(1)}% '
          'em ${valores.length} pares (limites: '
          'média>=${(_limiteMedia * 100).toStringAsFixed(0)}%, '
          'pior>=${(_limitePior * 100).toStringAsFixed(0)}%)',
      {'media': media, 'pior': pior},
    );
  }
}

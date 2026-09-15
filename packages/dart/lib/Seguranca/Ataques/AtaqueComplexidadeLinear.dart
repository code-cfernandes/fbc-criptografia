import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
/// reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
/// complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
/// um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
/// seria atacável resolvendo um sistema linear em vez de força bruta.
class AtaqueComplexidadeLinear extends Ataque {
  final int _bitsPorAmostra;
  final int _amostras;
  final double _limiteRelativo;

  AtaqueComplexidadeLinear({
    int bitsPorAmostra = 1024,
    int amostras = 5,
    double limiteRelativo = 0.4,
  }) : _bitsPorAmostra = bitsPorAmostra,
       _amostras = amostras,
       _limiteRelativo = limiteRelativo;

  @override
  String nome() => 'Complexidade linear (Berlekamp-Massey)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();

    final relativos = <double>[];
    var pior = 1.0;
    for (var a = 0; a < _amostras; a++) {
      final bytes = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        _bitsPorAmostra ~/ 8,
      );
      final bits = _paraBits(bytes, _bitsPorAmostra);
      final relativo = _berlekampMassey(bits) / _bitsPorAmostra;
      relativos.add(relativo);
      pior = min(pior, relativo);
    }

    final media = relativos.reduce((a, b) => a + b) / relativos.length;
    final vulneravel = pior < _limiteRelativo;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      'complexidade linear relativa: '
          'média=${(media * 100).toStringAsFixed(1)}%, '
          'pior=${(pior * 100).toStringAsFixed(1)}% de $_bitsPorAmostra bits '
          '(esperado ~50%; limite>=${(_limiteRelativo * 100).toStringAsFixed(0)}%)',
      {'media': media, 'pior': pior},
    );
  }

  List<int> _paraBits(List<int> bytes, int limite) {
    final bits = <int>[];
    for (var i = 0; i < bytes.length && bits.length < limite; i++) {
      final byte = bytes[i];
      for (var b = 7; b >= 0; b--) {
        bits.add((byte >> b) & 1);
      }
    }
    return bits.sublist(0, min(limite, bits.length));
  }

  /// Algoritmo de Berlekamp-Massey sobre GF(2).
  int _berlekampMassey(List<int> s) {
    final n = s.length;
    final c = List<int>.filled(n, 0);
    c[0] = 1;
    final b = List<int>.filled(n, 0);
    b[0] = 1;
    var l = 0;
    var m = -1;

    for (var i = 0; i < n; i++) {
      var d = s[i];
      for (var j = 1; j <= l; j++) {
        d ^= c[j] & s[i - j];
      }

      if (d == 1) {
        final t = List<int>.from(c);
        final shift = i - m;
        for (var j = 0; j + shift < n; j++) {
          c[j + shift] ^= b[j];
        }
        if (l <= i ~/ 2) {
          l = i + 1 - l;
          m = i;
          b.setAll(0, t);
        }
      }
    }

    return l;
  }
}

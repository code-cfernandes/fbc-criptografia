import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
/// IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
/// boa, essas diferenças são uniformes e únicas. Sinaliza:
///  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
///  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
///    que é o insumo básico de um ataque diferencial.
class AtaqueDiferencialKeystream extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;

  AtaqueDiferencialKeystream({this._amostras = 2000, this._tamanhoBloco = 32});

  @override
  String nome() => 'Diferencial do keystream (delta fixo no IV)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = randomBytes(alvo.chaveDeTeste().length);
    final tamanhoIv = alvo.tamanhoIv();

    final delta = Uint8List(tamanhoIv);
    delta[randomInt(0, tamanhoIv - 1)] = 1 << randomInt(0, 7);

    final totalBits = _tamanhoBloco * 8;
    final sempreZero = List<bool>.filled(totalBits, true);
    final sempreUm = List<bool>.filled(totalBits, true);
    final deltas = <String>{};

    for (var i = 0; i < _amostras; i++) {
      final iv = randomBytes(tamanhoIv);
      final iv2 = _xorBytes(iv, delta);

      final ks1 = alvo.gerarKeystreamBruto(
        chave,
        iv,
        'enc',
        _tamanhoBloco,
      );
      final ks2 = alvo.gerarKeystreamBruto(
        chave,
        iv2,
        'enc',
        _tamanhoBloco,
      );
      final d = _xorBytes(ks1, ks2);
      deltas.add(bytesToHex(d));

      for (var p = 0; p < d.length; p++) {
        final byte = d[p];
        for (var b = 0; b < 8; b++) {
          final idx = p * 8 + b;
          if (((byte >> b) & 1) == 1) {
            sempreZero[idx] = false;
          } else {
            sempreUm[idx] = false;
          }
        }
      }
    }

    var bitsFixos = 0;
    for (var idx = 0; idx < totalBits; idx++) {
      if (sempreZero[idx] || sempreUm[idx]) {
        bitsFixos++;
      }
    }
    final colisoes = _amostras - deltas.length;

    final vulneravel = bitsFixos > 0 || colisoes > 0;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'delta de 1 bit no IV: $bitsFixos bit(s) de saída fixo(s), '
          '$colisoes diferencial(is) repetido(s) em $_amostras amostras',
      {'bits_fixos': bitsFixos, 'colisoes': colisoes},
    );
  }

  Uint8List _xorBytes(Uint8List a, Uint8List b) {
    final out = Uint8List(a.length);
    for (var i = 0; i < a.length; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

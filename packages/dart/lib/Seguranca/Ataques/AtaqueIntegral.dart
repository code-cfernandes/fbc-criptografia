import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
/// um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
///
/// Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
/// soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
/// a saída como função do byte variado fica "quase bijetiva" e a soma tende a
/// zero MUITO mais que o acaso - um distinguisher clássico.
///
/// Como uma única (chave, IV) tem variância alta, acumula várias tentativas
/// para estimar o viés de forma estável (comparado a p=1/256).
class AtaqueIntegral extends Ataque {
  final int _tamanhoBloco;
  final int _posicoesIv;
  final int _posicoesChave;
  final int _tentativas;
  final double _limiteZ;

  AtaqueIntegral({
    this._tamanhoBloco = 32,
    this._posicoesIv = 8,
    this._posicoesChave = 8,
    this._tentativas = 16,
    this._limiteZ = 5.0,
  });

  @override
  String nome() => 'Integral (soma balanceada variando 1 byte de IV/chave)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tamIv = alvo.tamanhoIv();
    final tamChave = toBytes(alvo.chaveDeTeste()).length;

    final distinguidores = <String>[];
    var zerosTotal = 0;
    var bytesTotal = 0;

    for (var t = 0; t < _tentativas; t++) {
      final chave = randomBytes(tamChave);
      final ivBase = randomBytes(tamIv);

      for (var pos = 0; pos < min(_posicoesIv, tamIv); pos++) {
        final (xor, zeros) = _somarVariando(
          alvo,
          chave,
          ivBase,
          'iv',
          pos,
        );
        zerosTotal += zeros;
        bytesTotal += _tamanhoBloco;
        if (_todosZeros(xor)) {
          distinguidores.add('iv[$pos]');
        }
      }

      for (var pos = 0; pos < min(_posicoesChave, tamChave); pos++) {
        final (xor, zeros) = _somarVariando(
          alvo,
          chave,
          ivBase,
          'key',
          pos,
        );
        zerosTotal += zeros;
        bytesTotal += _tamanhoBloco;
        if (_todosZeros(xor)) {
          distinguidores.add('key[$pos]');
        }
      }
    }

    const p = 1 / 256;
    final esperado = bytesTotal * p;
    final desvio = sqrt(bytesTotal * p * (1 - p));
    final z = desvio > 0 ? (zerosTotal - esperado) / desvio : 0.0;

    final vulneravel = distinguidores.isNotEmpty || z > _limiteZ;

    if (distinguidores.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        'Soma balanceada (XOR zero) encontrada variando: '
            '${distinguidores.take(10).join(', ')}',
        {'distinguidores': distinguidores},
      );
    }

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      'bytes de saída zerados=$zerosTotal '
          '(esperado ~${esperado.toStringAsFixed(1)}, '
          'z=${z.toStringAsFixed(2)}) em $bytesTotal amostras; '
          'limite z=${_limiteZ.toStringAsFixed(1)}',
      {'zeros': zerosTotal, 'esperado': esperado, 'z': z},
    );
  }

  /// Retorna o XOR de 256 keystreams e quantos bytes deram zero.
  (Uint8List, int) _somarVariando(
    AlvoCriptografico alvo,
    Uint8List chave,
    Uint8List ivBase,
    String campo,
    int pos,
  ) {
    var xor = Uint8List(_tamanhoBloco);
    for (var v = 0; v < 256; v++) {
      final k = Uint8List.fromList(chave);
      final iv = Uint8List.fromList(ivBase);
      if (campo == 'iv') {
        iv[pos] = v;
      } else {
        k[pos] = v;
      }
      final ks = alvo.gerarKeystreamBruto(k, iv, 'enc', _tamanhoBloco);
      xor = _xorBytes(xor, ks);
    }
    var zeros = 0;
    for (var i = 0; i < xor.length; i++) {
      if (xor[i] == 0) {
        zeros++;
      }
    }
    return (xor, zeros);
  }

  bool _todosZeros(Uint8List buf) {
    for (var i = 0; i < buf.length; i++) {
      if (buf[i] != 0) {
        return false;
      }
    }
    return true;
  }

  Uint8List _xorBytes(Uint8List a, Uint8List b) {
    final out = Uint8List(a.length);
    for (var i = 0; i < a.length; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

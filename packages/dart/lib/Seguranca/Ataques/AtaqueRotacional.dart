import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

Uint8List _rotacionar(Uint8List buf, int k) {
  final n = buf.length;
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = buf[(i + k) % n];
  }
  return out;
}

/// Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
/// de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
/// `keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
/// byte e também coincidência direta do keystream.
class AtaqueRotacional extends Ataque {
  final int _tamanho;

  AtaqueRotacional({this._tamanho = 64});

  @override
  String nome() => 'Rotacional/slide (simetria por rotação)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = toBytes(alvo.chaveDeTeste());
    final iv = randomBytes(alvo.tamanhoIv());
    final ks1 = alvo.gerarKeystreamBruto(chave, iv, 'enc', _tamanho);

    final coincidencias = <String>[];
    for (var k = 1; k < chave.length; k++) {
      final ks2 = alvo.gerarKeystreamBruto(
        _rotacionar(chave, k),
        _rotacionar(iv, k),
        'enc',
        _tamanho,
      );

      if (_iguais(ks2, ks1)) {
        coincidencias.add('rotação $k: keystream idêntico');
        continue;
      }
      // metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
      final alvoRot = _rotacionar(ks1.sublist(0, 32), k);
      if (_iguais(ks2.sublist(0, 32), alvoRot)) {
        coincidencias.add('rotação $k: keystream rotacionado');
      }
    }

    final vulneravel = coincidencias.isNotEmpty;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      vulneravel
          ? 'Simetria rotacional encontrada: '
                '${coincidencias.take(5).join('; ')}'
          : 'Nenhuma das ${chave.length - 1} rotações de byte reproduziu o '
                'keystream',
      {'coincidencias': coincidencias},
    );
  }

  bool _iguais(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

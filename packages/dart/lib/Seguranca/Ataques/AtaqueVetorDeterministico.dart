import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico -
/// chamar a função duas vezes com a mesma entrada tem que dar o mesmo
/// resultado, sempre. Se não der, alguma fonte de aleatoriedade vazou pra
/// dentro de uma função que deveria ser pura.
///
/// De brinde, esse ataque imprime o "vetor de referência" (Known Answer
/// Vector) pra esse par key/iv.
class AtaqueVetorDeterministico extends Ataque {
  @override
  String nome() => 'Determinismo (vetor de referência key/iv fixos)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chaveFixa = repetir('K', toBytes(alvo.chaveDeTeste()).length);
    final ivFixo = Uint8List(alvo.tamanhoIv());

    final ks1 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);
    final ks2 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);
    final ks3 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);

    final deterministico =
        _iguais(ks1, ks2) && _iguais(ks2, ks3);

    return ResultadoAtaque(
      nome(),
      !deterministico,
      deterministico ? Severidade.info : Severidade.critica,
      deterministico
          ? 'Determinístico em 3 chamadas. Vetor de referência '
                '(key=64x"K", iv=zeros, prop=enc, 32 bytes): '
                '${bytesToHex(ks1)}'
          : 'NÃO determinístico! 3 chamadas com a mesma entrada deram '
                'resultados diferentes: ${bytesToHex(ks1)} / '
                '${bytesToHex(ks2)} / ${bytesToHex(ks3)}',
      {'vetor_hex': bytesToHex(ks1)},
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

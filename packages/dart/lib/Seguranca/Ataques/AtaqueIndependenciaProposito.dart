import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
/// chave do MAC ('mac'). Se os dois streams não forem independentes, um
/// atacante que recupere o keystream de dados (ataque de texto conhecido)
/// pode derivar a chave do MAC e FORJAR tokens válidos.
///
/// O teste procura dois sintomas de acoplamento:
///  1. a distância de Hamming média entre os streams deve ser ~50%;
///  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
///     uma máscara fixa, o mac é 100% previsível a partir do enc.
class AtaqueIndependenciaProposito extends Ataque {
  final int _amostras;
  final int _tamanho;

  AtaqueIndependenciaProposito({int amostras = 2000, int tamanho = 32})
    : _amostras = amostras,
      _tamanho = tamanho;

  @override
  String nome() =>
      'Independência entre keystreams de propósitos diferentes (enc x mac)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final distancias = <double>[];
    final mascaras = <String>{};

    for (var i = 0; i < _amostras; i++) {
      final chave = randomBytes(toBytes(alvo.chaveDeTeste()).length);
      final iv = randomBytes(alvo.tamanhoIv());

      final enc = alvo.gerarKeystreamBruto(chave, iv, 'enc', _tamanho);
      final mac = alvo.gerarKeystreamBruto(chave, iv, 'mac', _tamanho);

      distancias.add(bitsDiferentes(enc, mac) / (_tamanho * 8));
      mascaras.add(bytesToHex(_xorBytes(enc, mac)));
    }

    final media = distancias.reduce((a, b) => a + b) / distancias.length;
    final mascarasDistintas = mascaras.length;

    final vulneravel =
        media < 0.4 || media > 0.6 || mascarasDistintas < _amostras;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      'Hamming médio enc x mac=${(media * 100).toStringAsFixed(1)}% '
          '(esperado ~50%); $mascarasDistintas máscara(s) XOR distinta(s) em '
          '$_amostras amostras'
          '${mascarasDistintas < _amostras ? ' - MÁSCARA REPETIDA: mac '
                'previsível a partir de enc!' : ''}',
      {'media': media, 'mascaras_distintas': mascarasDistintas},
    );
  }

  Uint8List _xorBytes(Uint8List a, Uint8List b) {
    final len = a.length < b.length ? a.length : b.length;
    final out = Uint8List(len);
    for (var i = 0; i < len; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

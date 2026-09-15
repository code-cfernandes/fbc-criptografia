import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
/// Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
/// venham do mesmo texto, se comportam como se fossem de textos diferentes
/// (distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).
///
/// Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
/// parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
/// cifrar 500 textos diferentes.
class AtaqueCorrelacaoMesmoPlaintext extends Ataque {
  final int _amostras;
  final String _textoFixo;

  AtaqueCorrelacaoMesmoPlaintext({
    int amostras = 300,
    String textoFixo = 'MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR',
  }) : _amostras = amostras,
       _textoFixo = textoFixo;

  @override
  String nome() =>
      'Correlação entre ciphertexts do mesmo plaintext';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    final ciphertexts = <Uint8List>[];
    for (var i = 0; i < _amostras; i++) {
      final token = alvo.encrypt(_textoFixo);
      final decodificado = alvo.base64urlDecode(
        token.substring(alvo.prefixo().length),
      );
      ciphertexts.add(alvo.decompor(decodificado)['ciphertext']!);
    }

    // Compara pares aleatórios de ciphertexts (não todos contra todos,
    // pra manter o custo baixo) e mede a distância de Hamming média.
    final comparacoes =
        _min(500, (_amostras * (_amostras - 1)) ~/ 2);
    final distancias = <double>[];
    for (var c = 0; c < comparacoes; c++) {
      final i = randomInt(0, _amostras - 1);
      final j = randomInt(0, _amostras - 1);
      if (i == j) {
        continue;
      }
      distancias.add(_distanciaHammingRelativa(ciphertexts[i], ciphertexts[j]));
    }

    final media = distancias.reduce((a, b) => a + b) / distancias.length;

    // Também confere que nenhum PAR de ciphertexts é idêntico (o que
    // indicaria reuso de IV+key, capturado de outro ângulo).
    final unicos = ciphertexts.map(bytesToHex).toSet();
    final duplicatas = ciphertexts.length - unicos.length;

    final vulneravel = media < 0.4 || media > 0.6 || duplicatas > 0;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'distância de Hamming média entre ciphertexts do mesmo texto: '
          '${(media * 100).toStringAsFixed(1)}% (esperado ~50%), '
          '$duplicatas duplicata(s) exata(s) em $_amostras amostras',
      {'media': media, 'duplicatas': duplicatas},
    );
  }

  double _distanciaHammingRelativa(Uint8List a, Uint8List b) {
    final len = _min(a.length, b.length);
    if (len == 0) {
      return 0.5;
    }
    var diff = 0;
    for (var i = 0; i < len; i++) {
      diff += contarBits1(a[i] ^ b[i]);
    }
    return diff / (len * 8);
  }

  int _min(int a, int b) => a < b ? a : b;
}

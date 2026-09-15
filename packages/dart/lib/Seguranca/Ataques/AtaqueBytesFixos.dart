import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// As primeiras versões dessa cifra tinham um header fixo (43 bytes idênticos
/// sempre) ou um marcador constante (o '$' na posição 64). Esse ataque gera
/// vários tokens de textos diferentes e procura qualquer posição de byte que
/// NUNCA muda - isso é uma âncora que um atacante pode usar pra recuperar a
/// chave.
class AtaqueBytesFixos extends Ataque {
  final int _amostras;

  AtaqueBytesFixos({int amostras = 30}) : _amostras = amostras;

  @override
  String nome() => 'Bytes fixos entre tokens';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tokens = <String>[];
    for (var i = 0; i < _amostras; i++) {
      final texto =
          'TEXTO_VARIADO_$i' +
          repetir(String.fromCharCode(65 + (i % 26)), i % 10);
      tokens.add(alvo.encrypt(texto).substring(alvo.prefixo().length));
    }

    final decodificados = tokens.map(alvo.base64urlDecode).toList();
    final tamanhoMinimo = decodificados
        .map((d) => d.length)
        .reduce((a, b) => a < b ? a : b);

    final posicoesFixas = <int>[];
    for (var i = 0; i < tamanhoMinimo; i++) {
      final valores = decodificados.map((d) => d[i]).toSet();
      if (valores.length == 1) {
        posicoesFixas.add(i);
      }
    }

    if (posicoesFixas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        '${posicoesFixas.length} posição(ões) de byte fixas em $_amostras '
            'tokens: ${posicoesFixas.take(10).join(', ')}',
        {'posicoes': posicoesFixas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      '0 de $tamanhoMinimo posições fixas em $_amostras tokens',
    );
  }
}

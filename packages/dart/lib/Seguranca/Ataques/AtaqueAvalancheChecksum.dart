import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
/// interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
/// dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
/// posição específica significa que aquele byte quase não influencia o MAC -
/// uma pista forte de que a mistura tem um "ponto cego" estrutural.
///
/// Varre TODAS as posições/bits da entrada (não amostra aleatória) para
/// apontar exatamente onde está o ponto fraco.
class AtaqueAvalancheChecksum extends Ataque {
  final int _mensagensPorCombinacao;
  final int _tamanhoEntrada;
  final double _limiteMedia;
  final double _limitePiorCaso;

  AtaqueAvalancheChecksum({
    this._mensagensPorCombinacao = 10,
    this._tamanhoEntrada = 32,
    this._limiteMedia = 0.4,
    this._limitePiorCaso = 0.4,
  });

  @override
  String nome() => 'Efeito avalanche do checksum/MAC';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chaveMac = repetir('M', 32);

    final primeiro = alvo.checksumBruto('teste', chaveMac);
    final tamanhoSaida = primeiro.length;

    var somaGlobal = 0.0;
    var combinacoes = 0;
    var piorPosicao = -1;
    var piorBit = -1;
    var piorValor = 1.0;

    for (var pos = 0; pos < _tamanhoEntrada; pos++) {
      for (var bit = 0; bit < 8; bit++) {
        var soma = 0.0;
        for (var m = 0; m < _mensagensPorCombinacao; m++) {
          final entrada = randomBytes(_tamanhoEntrada);
          final alterada = Uint8List.fromList(entrada);
          alterada[pos] = alterada[pos] ^ (1 << bit);

          final h1 = alvo.checksumBruto(entrada, chaveMac);
          final h2 = alvo.checksumBruto(alterada, chaveMac);

          soma += bitsDiferentes(h1, h2) / (tamanhoSaida * 8);
        }
        final media = soma / _mensagensPorCombinacao;

        somaGlobal += media;
        combinacoes++;
        if (media < piorValor) {
          piorPosicao = pos;
          piorBit = bit;
          piorValor = media;
        }
      }
    }

    final mediaGlobal = somaGlobal / combinacoes;
    final vulneravel =
        mediaGlobal < _limiteMedia || piorValor < _limitePiorCaso;

    final Severidade severidade;
    if (!vulneravel) {
      severidade = Severidade.info;
    } else if (piorValor < 0.3) {
      severidade = Severidade.alta;
    } else {
      severidade = Severidade.media;
    }

    return ResultadoAtaque(
      nome(),
      vulneravel,
      severidade,
      'média global=${(mediaGlobal * 100).toStringAsFixed(1)}%; '
          'pior caso=${(piorValor * 100).toStringAsFixed(1)}% na '
          'entrada[posição=$piorPosicao, bit=$piorBit] sobre '
          '$tamanhoSaida bytes de MAC '
          '(limites: média>=${(_limiteMedia * 100).toStringAsFixed(0)}%, '
          'pior>=${(_limitePiorCaso * 100).toStringAsFixed(0)}%)',
      {
        'media_global': mediaGlobal,
        'pior': {
          'posicao': piorPosicao,
          'bit': piorBit,
          'valor': piorValor,
        },
      },
    );
  }
}

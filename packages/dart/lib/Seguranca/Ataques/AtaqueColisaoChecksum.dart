import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Procura colisões no checksum() via paradoxo do aniversário: gera muitas
/// mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
/// propósito aqui - testar resistência a colisão é uma propriedade do
/// ALGORITMO, independente de a chave ser secreta ou não; é assim que se
/// testa qualquer função de hash/MAC na prática).
///
/// Testa dois níveis:
/// 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
///    aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
///    tentativas pelo paradoxo do aniversário).
/// 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
///    estatisticamente com poucas dezenas de milhares de tentativas (o
///    paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
///    pra 50% de chance). Isso não quebra o MAC completo (que depende dos
///    32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
///    útil pra saber se a composição das rodadas está de fato preservando
///    a força total, ou se há alguma correlação entre elas.
class AtaqueColisaoChecksum extends Ataque {
  final int _amostras;

  AtaqueColisaoChecksum({this._amostras = 200000});

  @override
  String nome() => 'Colisão no checksum (paradoxo do aniversário)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    // chave conhecida de propósito - ver docblock
    final chaveDeMac = repetir('M', 32);

    alvo.checksumBruto('teste', chaveDeMac);

    final vistosCompleto = <String, Uint8List>{};
    final vistosTruncado = <String, Uint8List>{};
    List<Uint8List>? colisaoCompleta;
    List<Uint8List>? colisaoTruncada;

    for (var i = 0; i < _amostras; i++) {
      final mensagem = randomBytes(20);
      final hash = alvo.checksumBruto(mensagem, chaveDeMac);

      if (colisaoCompleta == null) {
        final chaveHash = bytesToHex(hash);
        final anterior = vistosCompleto[chaveHash];
        if (anterior != null) {
          colisaoCompleta = [anterior, mensagem];
        } else {
          vistosCompleto[chaveHash] = mensagem;
        }
      }

      if (colisaoTruncada == null) {
        final truncado = bytesToHex(hash.sublist(0, 4));
        final anterior = vistosTruncado[truncado];
        if (anterior != null) {
          colisaoTruncada = [anterior, mensagem];
        } else {
          vistosTruncado[truncado] = mensagem;
        }
      }

      if (colisaoCompleta != null && colisaoTruncada != null) {
        break;
      }
    }

    // Colisão no checksum COMPLETO com essa amostra pequena seria uma
    // falha estrutural séria (a probabilidade por acaso é desprezível).
    if (colisaoCompleta != null) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        'COLISÃO COMPLETA encontrada em ${vistosCompleto.length} amostras - '
            'isso não deveria acontecer por acaso. Investigar o algoritmo '
            'imediatamente.',
        {
          'msg1_hex': bytesToHex(colisaoCompleta[0]),
          'msg2_hex': bytesToHex(colisaoCompleta[1]),
        },
      );
    }

    // Colisão truncada (32 bits) é esperada estatisticamente - não é
    // "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
    // força que deveriam ter (nem mais, nem menos).
    final infoTruncada = colisaoTruncada != null
        ? 'colisão de 32 bits encontrada em ${vistosTruncado.length} '
              'amostras (esperado pelo paradoxo do aniversário)'
        : 'nenhuma colisão de 32 bits em ${vistosTruncado.length} amostras '
              '(um pouco abaixo do esperado, mas não conclusivo)';

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Nenhuma colisão completa em $_amostras amostras (esperado). '
          'Nível truncado (32 bits): $infoTruncada.',
      {
        'amostras_completo': vistosCompleto.length,
        'amostras_truncado': vistosTruncado.length,
      },
    );
  }
}

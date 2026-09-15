import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Procura linearidade no checksum, que seria fatal para um MAC:
///  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
///  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
///     cada a; se repetir muito, existe um diferencial de alta probabilidade
///     que ajuda a forjar MACs.
class AtaqueLinearidadeChecksum extends Ataque {
  final int _amostrasLinearidade;
  final int _amostrasDiferencial;
  final int _tamanhoEntrada;

  AtaqueLinearidadeChecksum({
    int amostrasLinearidade = 5000,
    int amostrasDiferencial = 500,
    int tamanhoEntrada = 32,
  }) : _amostrasLinearidade = amostrasLinearidade,
       _amostrasDiferencial = amostrasDiferencial,
       _tamanhoEntrada = tamanhoEntrada;

  @override
  String nome() => 'Linearidade e diferenciais do checksum';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chaveMac = repetir('M', 32);

    var relacoesLineares = 0;
    for (var i = 0; i < _amostrasLinearidade; i++) {
      final a = randomBytes(_tamanhoEntrada);
      final b = randomBytes(_tamanhoEntrada);
      final lhs = _xorBytes(
        alvo.checksumBruto(a, chaveMac),
        alvo.checksumBruto(b, chaveMac),
      );
      final rhs = alvo.checksumBruto(_xorBytes(a, b), chaveMac);
      if (_iguais(lhs, rhs)) {
        relacoesLineares++;
      }
    }

    var maxRepeticoesDiferencial = 0;
    for (var d = 0; d < 5; d++) {
      final delta = randomBytes(_tamanhoEntrada);
      final vistos = <String, int>{};
      for (var i = 0; i < _amostrasDiferencial; i++) {
        final a = randomBytes(_tamanhoEntrada);
        final dif = _xorBytes(
          alvo.checksumBruto(_xorBytes(a, delta), chaveMac),
          alvo.checksumBruto(a, chaveMac),
        );
        final chaveDif = bytesToHex(dif);
        vistos[chaveDif] = (vistos[chaveDif] ?? 0) + 1;
      }
      var maxVistos = 0;
      for (final c in vistos.values) {
        if (c > maxVistos) {
          maxVistos = c;
        }
      }
      maxRepeticoesDiferencial =
          maxRepeticoesDiferencial > maxVistos
          ? maxRepeticoesDiferencial
          : maxVistos;
    }

    final vulneravel =
        relacoesLineares > 0 || maxRepeticoesDiferencial > 1;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.critica : Severidade.info,
      '$relacoesLineares/$_amostrasLinearidade relações lineares; '
          'maior repetição de diferencial=$maxRepeticoesDiferencial '
          '(esperado 1)',
      {
        'relacoes_lineares': relacoesLineares,
        'max_repeticoes_diferencial': maxRepeticoesDiferencial,
      },
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

  bool _iguais(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

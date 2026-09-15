import 'dart:convert';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Esse é o ataque que pegou o bug mais sério que encontramos: quando a
/// distância de mistura era exatamente metade do bloco, TODOS os IVs
/// aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
/// Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
class AtaqueFoldEstrutural extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;

  AtaqueFoldEstrutural({int amostras = 5000, int tamanhoBloco = 32})
    : _amostras = amostras,
      _tamanhoBloco = tamanhoBloco;

  @override
  String nome() =>
      'Fold estrutural (metades/quartos/oitavos repetidos)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();

    final divisores = [2, 4, 8, 16]
        .where((d) => _tamanhoBloco % d == 0 && _tamanhoBloco / d >= 1)
        .toList();
    final ocorrencias = <int, int>{for (final d in divisores) d: 0};

    // Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
    // a chance de colisão por acaso é ~1/256^tam por par comparado -
    // desprezível para tam >= 2, então qualquer contagem > 0 já é
    // suspeita o bastante pra investigar (ajustamos a margem pra
    // fatias de 1-2 bytes, onde colisão por acaso é mais provável).
    for (var i = 0; i < _amostras; i++) {
      final ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        _tamanhoBloco,
      );
      for (final divisor in divisores) {
        final tamFatia = _tamanhoBloco ~/ divisor;
        final primeiraFatia = ks.sublist(0, tamFatia);
        for (var j = 1; j < divisor; j++) {
          if (bytesToHex(ks.sublist(j * tamFatia, j * tamFatia + tamFatia)) ==
              bytesToHex(primeiraFatia)) {
            ocorrencias[divisor] = ocorrencias[divisor]! + 1;
            break;
          }
        }
      }
    }

    int margem(int divisor) =>
        _tamanhoBloco / divisor <= 2 ? (_amostras * 0.01).truncate() + 3 : 5;

    final problemas = <int, int>{};
    for (final divisor in divisores) {
      final c = ocorrencias[divisor]!;
      if (c > margem(divisor)) {
        problemas[divisor] = c;
      }
    }

    if (problemas.isNotEmpty) {
      final detalhe = problemas.keys
          .map((d) => '1/$d do bloco repetido em ${problemas[d]}/$_amostras')
          .join(', ');
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        detalhe,
        {'ocorrencias': ocorrencias},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Nenhuma repetição estrutural acima do ruído esperado: ' +
          jsonEncode({
            for (final d in divisores) '$d': ocorrencias[d],
          }),
    );
  }
}

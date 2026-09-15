import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
/// de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
/// pra evitar falso-positivo por coincidência de valor). Uma dependência
/// ausente indica que a mistura não se propagou completamente - um atacante
/// poderia isolar e atacar aquele par de posições separadamente do resto.
class AtaqueCoberturaDependencia extends Ataque {
  final int _tamanhoBloco;
  final int _perturbacoesPorPar;

  AtaqueCoberturaDependencia({
    this._tamanhoBloco = 32,
    this._perturbacoesPorPar = 5,
  });

  @override
  String nome() => 'Cobertura de dependência (matriz entrada x saída)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tamanho = _tamanhoBloco;
    final chaveBase = Uint8List(tamanho);
    final iv = randomBytes(alvo.tamanhoIv());

    final ksBase = alvo.gerarKeystreamBruto(
      chaveBase,
      iv,
      'enc',
      tamanho,
    );
    if (chaveBase.length != tamanho) {
      // A chave precisa ter o mesmo tamanho do bloco pra esse teste
      // isolar 1 posição de cada vez sem wraparound. Se a cifra usa
      // chave de outro tamanho, pula esse ataque.
      throw SkipAtaqueException(
        'Teste requer chave do mesmo tamanho do bloco.',
      );
    }

    final paresIndependentes = <String>[];

    for (var posEntrada = 0; posEntrada < tamanho; posEntrada++) {
      final afetouAlgumaSaida = List<bool>.filled(tamanho, false);

      for (var p = 0; p < _perturbacoesPorPar; p++) {
        final chaveTeste = Uint8List.fromList(chaveBase);
        chaveTeste[posEntrada] = randomInt(1, 255);
        final ks = alvo.gerarKeystreamBruto(
          chaveTeste,
          iv,
          'enc',
          tamanho,
        );

        for (var posSaida = 0; posSaida < tamanho; posSaida++) {
          if (ks[posSaida] != ksBase[posSaida]) {
            afetouAlgumaSaida[posSaida] = true;
          }
        }
      }

      for (var posSaida = 0; posSaida < tamanho; posSaida++) {
        if (!afetouAlgumaSaida[posSaida]) {
          paresIndependentes.add(
            'entrada[$posEntrada] -> saída[$posSaida]',
          );
        }
      }
    }

    if (paresIndependentes.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.media,
        '${paresIndependentes.length} par(es) sem dependência detectável em '
            '$_perturbacoesPorPar tentativas cada',
        {'pares': paresIndependentes.take(20).toList()},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todos os ${tamanho * tamanho} pares (entrada, saída) mostraram '
          'dependência',
    );
  }
}

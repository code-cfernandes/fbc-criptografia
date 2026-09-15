import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
/// o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
/// posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
class AtaqueCoberturaDependenciaIV extends Ataque {
  final int _tamanhoBloco;
  final int _perturbacoesPorPosicao;

  AtaqueCoberturaDependenciaIV({
    this._tamanhoBloco = 32,
    this._perturbacoesPorPosicao = 5,
  });

  @override
  String nome() => 'Cobertura de dependência do IV (entrada x saída)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();
    final tamanhoIv = alvo.tamanhoIv();
    final ivBase = Uint8List(tamanhoIv);

    final ksBase = alvo.gerarKeystreamBruto(
      chave,
      ivBase,
      'enc',
      _tamanhoBloco,
    );

    final paresIndependentes = <String>[];

    for (var posIv = 0; posIv < tamanhoIv; posIv++) {
      final afetou = List<bool>.filled(_tamanhoBloco, false);

      for (var p = 0; p < _perturbacoesPorPosicao; p++) {
        final iv = Uint8List.fromList(ivBase);
        iv[posIv] = randomInt(1, 255);
        final ks = alvo.gerarKeystreamBruto(
          chave,
          iv,
          'enc',
          _tamanhoBloco,
        );

        for (var posSaida = 0; posSaida < _tamanhoBloco; posSaida++) {
          if (ks[posSaida] != ksBase[posSaida]) {
            afetou[posSaida] = true;
          }
        }
      }

      for (var posSaida = 0; posSaida < _tamanhoBloco; posSaida++) {
        if (!afetou[posSaida]) {
          paresIndependentes.add('iv[$posIv] -> saida[$posSaida]');
        }
      }
    }

    if (paresIndependentes.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        '${paresIndependentes.length} par(es) sem dependência detectável em '
            '$_perturbacoesPorPosicao tentativas cada',
        {'pares': paresIndependentes.take(20).toList()},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todas as $tamanhoIv posições do IV influenciam todas as '
          '$_tamanhoBloco posições de saída',
    );
  }
}

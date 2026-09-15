import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
/// (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
/// mesmo quando a maioria das entradas se comporta bem. Testa especificamente
/// esses casos extremos, que testes com entrada aleatória raramente cobrem.
class AtaqueIVsDegenerados extends Ataque {
  @override
  String nome() => 'IVs degenerados (zero, 0xFF, alternado)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();
    final tamanhoIv = alvo.tamanhoIv();
    const tamanhoBloco = 32;

    final casos = <String, Uint8List>{
      'zero': Uint8List(tamanhoIv),
      '0xFF': Uint8List(tamanhoIv)..fillRange(0, tamanhoIv, 0xff),
      'alternado 0xAA': Uint8List(tamanhoIv)..fillRange(0, tamanhoIv, 0xaa),
      'alternado 0x55': Uint8List(tamanhoIv)..fillRange(0, tamanhoIv, 0x55),
      'crescente': Uint8List.fromList(
        List<int>.generate(tamanhoIv, (i) => i),
      ),
    };

    final problemas = <String, Map<String, dynamic>>{};
    for (final entry in casos.entries) {
      final ks = alvo.gerarKeystreamBruto(
        chave,
        entry.value,
        'enc',
        tamanhoBloco,
      );

      const metade = tamanhoBloco ~/ 2;
      final periodico = bytesToHex(ks.sublist(0, metade)) ==
          bytesToHex(ks.sublist(metade, metade + metade));

      final bytesUnicos = ks.toSet().length;
      final poucaVariedade = bytesUnicos < tamanhoBloco * 0.5;

      if (periodico || poucaVariedade) {
        problemas[entry.key] = {
          'periodico': periodico,
          'bytes_unicos': bytesUnicos,
        };
      }
    }

    if (problemas.isNotEmpty) {
      final detalhe = problemas.entries
          .map((e) {
            final info = e.value;
            return '${e.key} (periódico='
                '${info['periodico'] == true ? 'sim' : 'não'}, '
                'bytes únicos=${info['bytes_unicos']}/$tamanhoBloco)';
          })
          .join('; ');
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        detalhe,
        problemas,
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Nenhum dos ${casos.length} IVs degenerados testados produziu '
          'saída anômala',
    );
  }
}

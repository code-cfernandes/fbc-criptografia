import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
/// produzir keystream anômalo (repetição, período curto, viés de bits ou
/// distribuição de bytes distorcida). Complementa o ataque de chaves
/// degeneradas, que só checa a saída do encrypt.
class AtaqueChavesFracas extends Ataque {
  final int _tamanho;
  final double _toleranciaBits;

  AtaqueChavesFracas({int tamanho = 2048, double toleranciaBits = 0.05})
    : _tamanho = tamanho,
      _toleranciaBits = toleranciaBits;

  @override
  String nome() => 'Chaves fracas (busca dirigida)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final len = toBytes(alvo.chaveDeTeste()).length;
    final casos = <(String, Uint8List)>[
      ('zeros', Uint8List(len)),
      ('0xFF', Uint8List(len)..fillRange(0, len, 0xff)),
      (
        'alternada AA/55',
        Uint8List.fromList(
          List<int>.generate(len, (i) => i % 2 == 0 ? 0xaa : 0x55),
        ),
      ),
      (
        'incremental',
        Uint8List.fromList(List<int>.generate(len, (i) => i & 0xff)),
      ),
      (
        'um bit',
        Uint8List.fromList(List<int>.generate(len, (i) => i == 0 ? 1 : 0)),
      ),
      ('byte repetido 0x01', Uint8List(len)..fillRange(0, len, 0x01)),
      (
        'padrão AB',
        Uint8List.fromList(
          List<int>.generate(len, (i) => i % 2 == 0 ? 0x41 : 0x42),
        ),
      ),
    ];

    final ivFixo = Uint8List(alvo.tamanhoIv());
    final anomalias = <String>[];

    for (final caso in casos) {
      final ks = alvo.gerarKeystreamBruto(
        caso.$2,
        ivFixo,
        'enc',
        _tamanho,
      );

      final blocos = <String>{};
      var repetidos = 0;
      for (var i = 0; i + 32 <= ks.length; i += 32) {
        final hex = bytesToHex(ks.sublist(i, i + 32));
        if (blocos.contains(hex)) {
          repetidos++;
        } else {
          blocos.add(hex);
        }
      }

      final fracaoUns = contarBitsBuffer(ks) / (ks.length * 8);
      final desvioBits = (fracaoUns - 0.5).abs();

      if (repetidos > 0) {
        anomalias.add('${caso.$1}: $repetidos bloco(s) repetido(s)');
      }
      if (desvioBits > _toleranciaBits) {
        anomalias.add(
          '${caso.$1}: viés de bits ${(fracaoUns * 100).toStringAsFixed(1)}%',
        );
      }
    }

    final vulneravel = anomalias.isNotEmpty;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      vulneravel
          ? 'Anomalias: ${anomalias.take(5).join('; ')}'
          : 'Nenhuma das ${casos.length} chaves fracas produziu keystream '
                'anômalo ($_tamanho bytes cada)',
      {'anomalias': anomalias},
    );
  }
}

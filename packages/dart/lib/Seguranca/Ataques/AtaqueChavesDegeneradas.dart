import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
/// (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
/// produzir keystream degenerado - e aqui testamos no pior cenário, com IV
/// zerado junto, pra isolar a contribuição da chave.
class AtaqueChavesDegeneradas extends Ataque {
  final int _tamanhoBloco;

  AtaqueChavesDegeneradas({int tamanhoBloco = 32})
    : _tamanhoBloco = tamanhoBloco;

  @override
  String nome() =>
      'Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tamChave = toBytes(alvo.chaveDeTeste()).length;
    final ivZero = Uint8List(alvo.tamanhoIv());

    final seqCrescente = Uint8List(512);
    for (var i = 0; i < 512; i++) {
      seqCrescente[i] = i % 256;
    }

    final casos = <String, Uint8List>{
      'zero': Uint8List(tamChave),
      '0xFF': Uint8List(tamChave)..fillRange(0, tamChave, 0xff),
      'alternada 0xAA': Uint8List(tamChave)..fillRange(0, tamChave, 0xaa),
      'alternada 0x55': Uint8List(tamChave)..fillRange(0, tamChave, 0x55),
      'repetida "A"': Uint8List(tamChave)..fillRange(0, tamChave, 0x41),
      'crescente': Uint8List.sublistView(seqCrescente, 0, tamChave),
    };

    final problemas = <String, Map<String, dynamic>>{};
    for (final entry in casos.entries) {
      final chave = entry.value;
      final ks = alvo.gerarKeystreamBruto(
        chave,
        ivZero,
        'enc',
        _tamanhoBloco,
      );

      final metade = _tamanhoBloco ~/ 2;
      final periodico = bytesToHex(ks.sublist(0, metade)) ==
          bytesToHex(ks.sublist(metade, metade + metade));
      final bytesUnicos = ks.toSet().length;

      if (periodico || bytesUnicos < _tamanhoBloco * 0.5) {
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
            return '${e.key} '
                '(periódico=${info['periodico'] == true ? 'sim' : 'não'}, '
                'bytes únicos=${info['bytes_unicos']}/$_tamanhoBloco)';
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
      'Nenhuma das ${casos.length} chaves degeneradas testadas produziu '
          'saída anômala',
    );
  }
}

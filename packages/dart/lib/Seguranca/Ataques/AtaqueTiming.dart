import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';

/// Se a comparação de integridade não for de tempo constante (ex: usar ===
/// em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
/// iniciais do campo de integridade batem, comparando o tempo de resposta -
/// e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
///
/// Esse teste gera um token válido, cria versões adulteradas onde o campo
/// de integridade erra em posições DIFERENTES (início vs. fim do campo), e
/// compara o tempo médio de decrypt() entre os grupos. Uma diferença
/// estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
/// último byte" indica uma comparação vulnerável a timing.
///
/// IMPORTANTE: testes de timing têm MUITO ruído (garbage collector, JIT,
/// agendamento do SO). Isso é uma checagem heurística grosseira, não uma
/// prova formal - trate qualquer resultado "vulnerável" como um convite pra
/// investigar o código-fonte diretamente, e um resultado "resistiu" como
/// "não detectei nesse experimento", não como garantia.
class AtaqueTiming extends Ataque {
  final int _repeticoesPorGrupo;

  AtaqueTiming({int repeticoesPorGrupo = 400})
    : _repeticoesPorGrupo = repeticoesPorGrupo;

  @override
  String nome() => 'Timing da verificação de integridade';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException(
        'Precisa de base64url_encode/decode do alvo.',
      );
    }

    final token = alvo.encrypt('MENSAGEM_PARA_TESTE_DE_TIMING');
    final decodificado = alvo.base64urlDecode(
      token.substring(alvo.prefixo().length),
    );
    final campos = alvo.decompor(decodificado);
    final tamanhoIntegridade = campos['integridade']!.length;

    int medirGrupo(int posicaoErro) {
      final tempos = <int>[];
      for (var r = 0; r < _repeticoesPorGrupo; r++) {
        final integ = Uint8List.fromList(campos['integridade']!);
        integ[posicaoErro] = integ[posicaoErro] ^ 0x01;

        final camposAdulterados = <String, Uint8List>{
          'integridade': integ,
          'ciphertext': campos['ciphertext']!,
          'iv': campos['iv']!,
        };

        final tokenAdulterado =
            alvo.prefixo() +
            alvo.base64urlEncode(alvo.recompor(camposAdulterados));

        final cronometro = Stopwatch()..start();
        try {
          alvo.decrypt(tokenAdulterado);
        } catch (_) {
          // esperado
        }
        cronometro.stop();
        tempos.add(cronometro.elapsedMicroseconds);
      }
      tempos.sort();
      // usa a mediana em vez da média - muito mais robusta a outliers
      // de agendamento do SO, comum em testes de timing em ambiente
      // compartilhado.
      return tempos[tempos.length ~/ 2];
    }

    // Grupo A: erro logo no primeiro byte do campo de integridade.
    // Grupo B: erro no último byte.
    // Repete várias rodadas intercaladas pra diluir variação de carga
    // da máquina ao longo do tempo (evita viés de "a máquina esquentou").
    final medianasA = <int>[];
    final medianasB = <int>[];
    for (var rodada = 0; rodada < 8; rodada++) {
      medianasA.add(medirGrupo(0));
      medianasB.add(medirGrupo(tamanhoIntegridade - 1));
    }

    final medianaA = medianasA.reduce((s, x) => s + x) / medianasA.length;
    final medianaB = medianasB.reduce((s, x) => s + x) / medianasB.length;
    final diferencaRelativa =
        (medianaA - medianaB).abs() /
        (medianaA > medianaB ? medianaA : medianaB);

    // Limite arbitrário e conservador: só marca como suspeito se a
    // diferença for grande o bastante pra não ser só ruído de máquina
    // (na prática, comparações vulneráveis costumam mostrar diferenças
    // bem mais óbvias que isso quando o campo é curto).
    final vulneravel = diferencaRelativa > 0.15;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.media : Severidade.info,
      'mediana erro-no-início=${medianaA.toStringAsFixed(0)}us, '
          'mediana erro-no-fim=${medianaB.toStringAsFixed(0)}us, '
          'diferença relativa=${(diferencaRelativa * 100).toStringAsFixed(1)}% '
          '(limite=15%). '
          '${vulneravel ? 'Diferença suspeita - investigar se a comparação '
                'usa hash_equals().' : 'Sem diferença clara nesse '
                'experimento (lembrando: teste heurístico, não prova '
                'formal).'}',
      {'mediana_inicio_ns': medianaA, 'mediana_fim_ns': medianaB},
    );
  }
}

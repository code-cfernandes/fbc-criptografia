import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';

/// Orquestra a execução de uma coleção de ataques contra um alvo.
class SuiteDeAtaques {
  final List<Ataque> _ataques = [];

  SuiteDeAtaques adicionar(Ataque ataque) {
    _ataques.add(ataque);
    return this;
  }

  List<ResultadoAtaque> rodar(AlvoCriptografico alvo) {
    final resultados = <ResultadoAtaque>[];
    for (final ataque in _ataques) {
      try {
        resultados.add(ataque.executar(alvo));
      } on SkipAtaqueException catch (e) {
        resultados.add(
          ResultadoAtaque(
            ataque.nome(),
            false,
            Severidade.pulado,
            'Pulado: $e',
          ),
        );
      } catch (e) {
        resultados.add(
          ResultadoAtaque(
            ataque.nome(),
            true,
            Severidade.erro,
            'Erro ao executar: $e',
          ),
        );
      }
    }
    return resultados;
  }

  /// Roda e imprime um relatório direto no console.
  bool rodarEImprimir(AlvoCriptografico alvo) {
    final resultados = rodar(alvo);
    var vulnerabilidades = 0;

    print('=' * 70);
    print('RELATÓRIO DA SUÍTE DE ATAQUES');
    print('=' * 70);
    print('');

    for (final r in resultados) {
      print(r.linhaResumo());
      if (r.vulneravel &&
          r.severidade != Severidade.pulado &&
          r.severidade != Severidade.demonstracao) {
        vulnerabilidades++;
      }
    }

    print('');
    print('=' * 70);
    if (vulnerabilidades == 0) {
      print(
        'RESUMO: nenhuma vulnerabilidade encontrada em '
        '${resultados.length} ataque(s).',
      );
    } else {
      print(
        'RESUMO: $vulnerabilidades vulnerabilidade(s) encontrada(s) de '
        '${resultados.length} ataque(s) rodados!',
      );
    }
    print('=' * 70);

    return vulnerabilidades == 0;
  }
}

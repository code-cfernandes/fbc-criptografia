import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
/// correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
/// posições de saída é exatamente o tipo de estrutura que o antigo bug da
/// "metade igual" produzia - e que a autocorrelação temporal pode não pegar.
class AtaqueCorrelacaoPosicoes extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;
  final double _limiteCorrelacao;

  AtaqueCorrelacaoPosicoes({
    int amostras = 3000,
    int tamanhoBloco = 32,
    double limiteCorrelacao = 0.15,
  }) : _amostras = amostras,
       _tamanhoBloco = tamanhoBloco,
       _limiteCorrelacao = limiteCorrelacao;

  @override
  String nome() => 'Correlação entre posições do bloco';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();

    final blocos = <Uint8List>[];
    for (var i = 0; i < _amostras; i++) {
      blocos.add(
        alvo.gerarKeystreamBruto(
          chave,
          randomBytes(alvo.tamanhoIv()),
          'enc',
          _tamanhoBloco,
        ),
      );
    }

    final suspeitos = <String>[];
    var pior = 0.0;

    for (var a = 0; a < _tamanhoBloco; a++) {
      for (var b = a + 1; b < _tamanhoBloco; b++) {
        final corr = _pearson(blocos, a, b);
        if (corr.abs() > pior.abs()) {
          pior = corr;
        }
        if (corr.abs() > _limiteCorrelacao) {
          suspeitos.add('posições $a-$b (r=${corr.toStringAsFixed(3)})');
        }
      }
    }

    if (suspeitos.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        '${suspeitos.length} par(es) correlacionado(s): '
            '${suspeitos.take(10).join('; ')}',
        {'suspeitos': suspeitos},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Nenhum par de posições correlacionado acima de '
          '${_limiteCorrelacao.toStringAsFixed(2)} '
          '(pior |r|=${pior.abs().toStringAsFixed(3)})',
    );
  }

  double _pearson(List<Uint8List> blocos, int a, int b) {
    final n = blocos.length;
    var ma = 0.0;
    var mb = 0.0;
    for (final d in blocos) {
      ma += d[a];
      mb += d[b];
    }
    ma /= n;
    mb /= n;

    var num = 0.0;
    var da = 0.0;
    var db = 0.0;
    for (final d in blocos) {
      final xa = d[a] - ma;
      final xb = d[b] - mb;
      num += xa * xb;
      da += xa * xa;
      db += xb * xb;
    }

    return da > 0 && db > 0 ? num / sqrt(da * db) : 0.0;
  }
}

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
/// gerado (efeito avalanche). Números muito abaixo disso indicam difusão
/// fraca - foi o que achamos quando o número de rodadas de mistura era
/// baixo demais numa das versões anteriores.
class AtaqueAvalanche extends Ataque {
  final int _amostras;
  final int _tamanhoBloco;
  final double _limiteMedia;
  final double _limitePiorCaso;

  AtaqueAvalanche({
    int amostras = 3000,
    int tamanhoBloco = 32,
    double limiteMedia = 0.45,
    double limitePiorCaso = 0.3,
  }) : _amostras = amostras,
       _tamanhoBloco = tamanhoBloco,
       _limiteMedia = limiteMedia,
       _limitePiorCaso = limitePiorCaso;

  @override
  String nome() => 'Efeito avalanche';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();
    final tamanhoIv = alvo.tamanhoIv();

    final valores = <double>[];
    for (var t = 0; t < _amostras; t++) {
      final iv1 = randomBytes(tamanhoIv);
      final iv2 = iv1.sublist(0);
      final pos = randomInt(0, tamanhoIv - 1);
      iv2[pos] = iv2[pos] ^ (1 << randomInt(0, 7));

      final ks1 = alvo.gerarKeystreamBruto(
        chave,
        iv1,
        'enc',
        _tamanhoBloco,
      );
      final ks2 = alvo.gerarKeystreamBruto(
        chave,
        iv2,
        'enc',
        _tamanhoBloco,
      );

      valores.add(bitsDiferentes(ks1, ks2) / (_tamanhoBloco * 8));
    }

    valores.sort();
    final n = valores.length;
    final media = valores.reduce((a, b) => a + b) / n;
    final piorCaso = valores[0];

    final vulneravel =
        media < _limiteMedia || piorCaso < _limitePiorCaso;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'média=${(media * 100).toStringAsFixed(1)}%, '
          'pior caso=${(piorCaso * 100).toStringAsFixed(1)}%, '
          'percentil 1%='
          '${(valores[(n * 0.01).truncate()] * 100).toStringAsFixed(1)}% '
          '(limites: média>=${(_limiteMedia * 100).toStringAsFixed(0)}%, '
          'pior>=${(_limitePiorCaso * 100).toStringAsFixed(0)}%)',
      {'media': media, 'pior_caso': piorCaso},
    );
  }
}

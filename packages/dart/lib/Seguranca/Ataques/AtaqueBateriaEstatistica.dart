import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
/// global (monobit), frequência por posição de bit, teste de runs e frequência
/// por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
/// e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
///
/// Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
/// pra não depender de funções numéricas especiais.
class AtaqueBateriaEstatistica extends Ataque {
  final int _tamanho;
  final double _zLimite;

  AtaqueBateriaEstatistica({int tamanho = 16384, double zLimite = 4.0})
    : _tamanho = tamanho,
      _zLimite = zLimite;

  @override
  String nome() => 'Bateria estatística de bits (monobit/runs/blocos)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      _tamanho,
    );

    final bits = _paraBits(ks);
    final n = bits.length;
    final problemas = <String>[];
    final dados = <String, dynamic>{};

    // 1) Monobit: soma +1/-1
    var soma = 0;
    for (final b in bits) {
      soma += b == 1 ? 1 : -1;
    }
    final zMonobit = soma.abs() / sqrt(n);
    dados['monobit_z'] = zMonobit;
    if (zMonobit > _zLimite) {
      problemas.add('monobit z=${zMonobit.toStringAsFixed(2)}');
    }

    // 2) Frequência por posição de bit
    final unsPorPos = List<int>.filled(8, 0);
    final contaPorPos = List<int>.filled(8, 0);
    for (var i = 0; i < ks.length; i++) {
      final byte = ks[i];
      for (var b = 0; b < 8; b++) {
        if (((byte >> b) & 1) == 1) {
          unsPorPos[b]++;
        }
        contaPorPos[b]++;
      }
    }
    final posViesadas = <int, double>{};
    for (var b = 0; b < 8; b++) {
      final frac = unsPorPos[b] / contaPorPos[b];
      final z = (frac - 0.5).abs() / (0.5 / sqrt(contaPorPos[b]));
      if (z > _zLimite) {
        posViesadas[b] = frac;
      }
    }
    dados['bit_posicao_viesadas'] = posViesadas;
    if (posViesadas.isNotEmpty) {
      problemas.add(
        'viés por posição de bit: ${posViesadas.keys.join(', ')}',
      );
    }

    // 3) Runs test
    final pi = bits.reduce((a, b) => a + b) / n;
    if ((pi - 0.5).abs() < 2 / sqrt(n)) {
      var runs = 1;
      for (var i = 1; i < n; i++) {
        if (bits[i] != bits[i - 1]) {
          runs++;
        }
      }
      final esperado = 2 * n * pi * (1 - pi);
      final desvio = 2 * sqrt(2 * n) * pi * (1 - pi);
      final zRuns = (runs - esperado).abs() / desvio;
      dados['runs_z'] = zRuns;
      if (zRuns > _zLimite) {
        problemas.add('runs z=${zRuns.toStringAsFixed(2)}');
      }
    }

    // 4) Frequência por bloco (M = 128 bits)
    const m = 128;
    final numBlocos = n ~/ m;
    if (numBlocos > 0) {
      var chi = 0.0;
      for (var i = 0; i < numBlocos; i++) {
        var uns = 0;
        for (var j = 0; j < m; j++) {
          uns += bits[i * m + j];
        }
        chi += pow(uns / m - 0.5, 2).toDouble();
      }
      chi *= 4 * m;
      final zBlocos = (chi - numBlocos) / sqrt(2 * numBlocos);
      dados['blocos_chi2'] = chi;
      dados['blocos_z'] = zBlocos;
      if (zBlocos > _zLimite) {
        problemas.add('frequência por bloco chi2=${chi.toStringAsFixed(1)}');
      }
    }

    if (problemas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.media,
        problemas.join('; '),
        dados,
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'monobit z=${zMonobit.toStringAsFixed(2)}, '
          'runs z=${((dados['runs_z'] as num?) ?? 0.0).toStringAsFixed(2)}, '
          'blocos chi2='
          '${((dados['blocos_chi2'] as num?) ?? 0.0).toStringAsFixed(1)} - '
          'todos abaixo do limite z=${_zLimite.toStringAsFixed(0)}',
      dados,
    );
  }

  List<int> _paraBits(List<int> bytes) {
    final bits = <int>[];
    for (var i = 0; i < bytes.length; i++) {
      final byte = bytes[i];
      for (var b = 7; b >= 0; b--) {
        bits.add((byte >> b) & 1);
      }
    }
    return bits;
  }
}

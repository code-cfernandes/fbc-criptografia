import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
/// gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
/// locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
/// aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
class AtaqueSerialBits extends Ataque {
  final int _tamanho;
  final List<int> _ordens;

  AtaqueSerialBits({int tamanho = 4096, List<int> ordens = const [2, 3, 4]})
    : _tamanho = tamanho,
      _ordens = ordens;

  @override
  String nome() => 'Teste serial (padrões de bits sobrepostos)';

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

    for (final m in _ordens) {
      final total = 1 << m;
      final contagem = List<int>.filled(total, 0);
      final janelas = n - m + 1;

      for (var i = 0; i < janelas; i++) {
        var v = 0;
        for (var j = 0; j < m; j++) {
          v = (v << 1) | bits[i + j];
        }
        contagem[v]++;
      }

      final esperado = janelas / total;
      var chi2 = 0.0;
      for (final c in contagem) {
        chi2 += pow(c - esperado, 2).toDouble() / esperado;
      }
      final dof = total - 1;
      // Wilson-Hilferty: aproxima chi² por normal de forma bem mais precisa
      // para dof pequeno. O z "ingênuo" (chi2-dof)/sqrt(2*dof) dá ~5% de falso
      // positivo em dof=3 (m=2); este fica em ~0.005%.
      final z = (pow(chi2 / dof, 1 / 3).toDouble() -
              (1 - 2 / (9 * dof))) /
          sqrt(2 / (9 * dof));
      dados['m$m'] = {'chi2': chi2, 'z': z};

      if (z > 6.0) {
        problemas.add(
          'm=$m chi2=${chi2.toStringAsFixed(1)} (z=${z.toStringAsFixed(1)})',
        );
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
      'Padrões sobrepostos de 2/3/4 bits com frequência uniforme',
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

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
/// primeira metade do keystream e mede a taxa de acerto na segunda metade.
/// Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
/// Qualquer coisa acima disso indica que os bits carregam dependência
/// explorável - o embrião de um ataque de predição de estado.
class AtaquePreditorDeBits extends Ataque {
  final int _tamanho;
  final int _contexto;
  final double _limiteTaxa;

  AtaquePreditorDeBits({
    this._tamanho = 16384,
    this._contexto = 8,
    this._limiteTaxa = 0.55,
  });

  @override
  String nome() => 'Previsibilidade de bits (preditor por contexto)';

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
    final k = _contexto;
    final total = 1 << k;
    final metade = n ~/ 2;

    final uns = List<int>.filled(total, 0);
    final cont = List<int>.filled(total, 0);
    for (var i = k; i < metade; i++) {
      final ctx = _contextoDe(bits, i, k);
      uns[ctx] += bits[i];
      cont[ctx]++;
    }

    var acertos = 0;
    var testes = 0;
    for (var i = metade; i < n; i++) {
      final ctx = _contextoDe(bits, i, k);
      if (cont[ctx] == 0) {
        continue;
      }
      final predicao = uns[ctx] * 2 > cont[ctx] ? 1 : 0;
      if (predicao == bits[i]) {
        acertos++;
      }
      testes++;
    }

    final taxa = testes > 0 ? acertos / testes : 0.5;
    final vulneravel = taxa > _limiteTaxa;

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      'taxa de acerto=${(taxa * 100).toStringAsFixed(2)}% com contexto de '
          '$k bits (esperado ~50%, limite='
          '${(_limiteTaxa * 100).toStringAsFixed(0)}%) sobre $testes testes',
      {'taxa': taxa, 'testes': testes},
    );
  }

  int _contextoDe(List<int> bits, int i, int k) {
    var ctx = 0;
    for (var j = i - k; j < i; j++) {
      ctx = (ctx << 1) | bits[j];
    }
    return ctx;
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

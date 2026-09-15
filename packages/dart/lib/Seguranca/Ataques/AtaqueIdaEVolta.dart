import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
/// de decrypt precisa devolver o texto original, em qualquer tamanho.
/// Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
/// segurança mais sério por trás.
class AtaqueIdaEVolta extends Ataque {
  final int _tamanhoMaximo;

  AtaqueIdaEVolta({this._tamanhoMaximo = 130});

  @override
  String nome() => 'Ida-e-volta (round trip)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final falhas = <String>[];
    for (var len = 0; len <= _tamanhoMaximo; len++) {
      final texto = repetir('Q', len);
      try {
        final token = alvo.encrypt(texto);
        final decifrado = alvo.decrypt(token);
        if (decifrado != texto) {
          falhas.add('$len');
        }
      } catch (e) {
        falhas.add('$len (erro: $e)');
      }
    }

    if (falhas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        'Falhou em ${falhas.length} tamanho(s): '
            '${falhas.take(10).join(', ')}',
        {'falhas': falhas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todos os ${_tamanhoMaximo + 1} tamanhos (0 a $_tamanhoMaximo) OK',
    );
  }
}

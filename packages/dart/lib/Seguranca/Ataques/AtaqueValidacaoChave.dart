import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
/// rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
/// bytes válida deve funcionar. Uma validação frouxa aqui vira uma chave mais
/// curta (e mais fraca) na prática.
class AtaqueValidacaoChave extends Ataque {
  final List<int> _tamanhos;

  AtaqueValidacaoChave({List<int>? tamanhos})
    : _tamanhos = tamanhos ?? const [0, 1, 16, 31, 33, 64];

  @override
  String nome() => 'Validação do tamanho da chave';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException(
        'Precisa de CriptografiaAlvo para trocar a chave.',
      );
    }

    final chaveOriginal = alvo.chaveDeTeste();
    final aceitasIndevidamente = <int>[];
    var validaRejeitada = false;

    try {
      for (final len in _tamanhos) {
        CriptografiaAlvo(repetir('K', len));
        try {
          alvo.encrypt('x');
          aceitasIndevidamente.add(len);
        } catch (_) {
          // esperado
        }
      }

      CriptografiaAlvo(repetir('K', 32));
      try {
        alvo.encrypt('x');
      } catch (_) {
        validaRejeitada = true;
      }
    } finally {
      CriptografiaAlvo.definirChaveGlobal(chaveOriginal);
    }

    final vulneravel = aceitasIndevidamente.isNotEmpty || validaRejeitada;

    final detalhes = <String>[];
    if (aceitasIndevidamente.isNotEmpty) {
      detalhes.add(
        'chaves de tamanho inválido aceitas: ${aceitasIndevidamente.join(', ')}',
      );
    }
    if (validaRejeitada) {
      detalhes.add('chave válida de 32 bytes foi rejeitada');
    }

    return ResultadoAtaque(
      nome(),
      vulneravel,
      vulneravel ? Severidade.alta : Severidade.info,
      vulneravel
          ? detalhes.join('; ')
          : 'Tamanhos inválidos rejeitados e chave de 32 bytes aceita',
    );
  }
}

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Garante que um token só decifra com a chave correta: com qualquer outra
/// chave de 32 bytes, decrypt() tem que lançar. Verifica também que a chave
/// errada não "quase funciona" (ex: aceitar às vezes por MAC fraco).
///
/// Cuidado: CriptografiaAlvo escreve a chave no estado global; a chave
/// original é restaurada no final pra não afetar os outros ataques.
class AtaqueChaveErrada extends Ataque {
  final int _tentativas;

  AtaqueChaveErrada({this._tentativas = 30});

  @override
  String nome() => 'Rejeição de chave incorreta';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException(
        'Precisa de CriptografiaAlvo para trocar a chave.',
      );
    }

    final chaveOriginal = alvo.chaveDeTeste();

    final tokens = <String>[];
    for (var i = 0; i < _tentativas; i++) {
      tokens.add(alvo.encrypt('MENSAGEM_SECRETA_$i'));
    }

    final aceitos = <String>[];
    try {
      for (var i = 0; i < tokens.length; i++) {
        CriptografiaAlvo(bytesToHex(randomBytes(16)));
        try {
          final r = alvo.decrypt(tokens[i]);
          aceitos.add('tentativa $i aceitou (retornou $r)');
        } catch (_) {
          // esperado
        }
      }
    } finally {
      CriptografiaAlvo.definirChaveGlobal(chaveOriginal);
    }

    if (aceitos.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        '${aceitos.length} de $_tentativas tokens foram aceitos com a chave '
            'errada',
        {'exemplos': aceitos.take(5).toList()},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Nenhum dos $_tentativas tokens foi aceito com chave incorreta',
    );
  }
}

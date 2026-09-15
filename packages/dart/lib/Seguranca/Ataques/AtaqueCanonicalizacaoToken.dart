import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';

/// Um mesmo token não deveria ter múltiplas representações textuais válidas.
/// Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
/// padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
/// lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
/// token. Isso é "token smuggling": sistemas que comparam/usam a string do
/// token de formas diferentes (cache, WAF, deduplicação/replay) discordam
/// sobre o que ele significa.
class AtaqueCanonicalizacaoToken extends Ataque {
  @override
  String nome() => 'Canonicalização do token (base64 não-canônico)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException(
        'Precisa de base64url_encode/decode do alvo.',
      );
    }

    const texto = 'MENSAGEM_DE_TESTE_DE_CANONICALIZACAO';
    final token = alvo.encrypt(texto);
    final prefixo = alvo.prefixo();
    final corpo = token.substring(prefixo.length);
    final meio = corpo.length ~/ 2;

    final variantes = <String, String>{};
    for (final p in [0, meio, corpo.length - 1]) {
      variantes['espaço na posição $p'] =
          prefixo + corpo.substring(0, p) + ' ' + corpo.substring(p);
      variantes['newline na posição $p'] =
          prefixo + corpo.substring(0, p) + '\n' + corpo.substring(p);
      variantes['tab na posição $p'] =
          prefixo + corpo.substring(0, p) + '\t' + corpo.substring(p);
    }
    variantes['alfabeto padrão (+/)'] =
        prefixo + corpo.replaceAll('-', '+').replaceAll('_', '/');
    variantes['padding "=" extra'] = prefixo + corpo + '=';
    variantes['caractere inválido no meio'] =
        prefixo + corpo.substring(0, meio) + '!' + corpo.substring(meio);

    final aceitas = <String>[];
    for (final entry in variantes.entries) {
      final v = entry.value;
      if (v == token) {
        continue;
      }
      try {
        if (alvo.decrypt(v) == texto) {
          aceitas.add(entry.key);
        }
      } catch (_) {
        // esperado
      }
    }

    if (aceitas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.media,
        '${aceitas.length} variante(s) textualmente diferente(s) decifram '
            'para o mesmo texto: ${aceitas.join('; ')}',
        {'variantes_aceitas': aceitas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todas as ${variantes.length} variantes não-canônicas foram rejeitadas',
    );
  }
}

import 'dart:convert';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Robustez do parser de tokens: qualquer entrada que não seja um token
/// íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
/// devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
/// é uma porta pra bugs de validação e "token smuggling".
class AtaqueTokensMalformados extends Ataque {
  @override
  String nome() => 'Tokens malformados (fuzzing de entrada)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final token = alvo.encrypt('MENSAGEM_VALIDA_PARA_TESTE');
    final prefixo = alvo.prefixo();
    final corpo = token.substring(prefixo.length);

    final casos = <String, String>{
      'vazio': '',
      'só prefixo': prefixo,
      'prefixo errado': 'XXX$corpo',
      'base64 inválido': '$prefixo!!!@@@###',
      'bytes extras no fim': '${token}AAAA',
      'bytes extras no início': 'AAAA$token',
    };
    for (var len = 1; len < token.length; len++) {
      casos['truncado em $len'] = token.substring(0, len);
    }
    for (var i = 0; i < 20; i++) {
      casos['lixo aleatório $i'] = prefixo + bytesToHex(randomBytes(16));
    }

    final aceitos = <String>[];
    for (final entry in casos.entries) {
      try {
        final r = alvo.decrypt(entry.value);
        aceitos.add(
          '${entry.key} -> aceito (retornou ${utf8.encode(r).length} bytes)',
        );
      } catch (_) {
        // comportamento esperado
      }
    }

    if (aceitos.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.critica,
        '${aceitos.length} entrada(s) malformada(s) foram ACEITAS em vez de '
            'rejeitadas',
        {'exemplos': aceitos.take(10).toList()},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'Todas as ${casos.length} entradas malformadas foram rejeitadas',
    );
  }
}

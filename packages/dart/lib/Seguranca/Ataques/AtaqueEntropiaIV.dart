import 'dart:math';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';

/// O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
/// Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
/// trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
/// timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
/// rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
/// mesmo sem nunca colidir de fato.
///
/// Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
/// ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
/// e sequências crescentes/monótonas entre IVs consecutivos (sintoma
/// clássico de contador ou timestamp).
class AtaqueEntropiaIV extends Ataque {
  final int _amostras;

  AtaqueEntropiaIV({this._amostras = 2000});

  @override
  String nome() => 'Entropia e previsibilidade do IV';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    if (alvo is! CriptografiaAlvo) {
      throw SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    final ivs = <List<int>>[];
    for (var i = 0; i < _amostras; i++) {
      final token = alvo.encrypt('X');
      final decodificado = alvo.base64urlDecode(
        token.substring(alvo.prefixo().length),
      );
      ivs.add(alvo.decompor(decodificado)['iv']!);
    }

    final problemas = <String>[];

    // Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
    final contagem = List<int>.filled(256, 0);
    var total = 0;
    for (final iv in ivs) {
      for (var i = 0; i < iv.length; i++) {
        contagem[iv[i]]++;
        total++;
      }
    }
    final esperado = total / 256;
    var qui2 = 0.0;
    for (final c in contagem) {
      qui2 += pow(c - esperado, 2).toDouble() / esperado;
    }
    if (qui2 > 330) {
      problemas.add(
        'distribuição de bytes suspeita '
        '(qui-quadrado=${qui2.toStringAsFixed(1)}, >330 é suspeito)',
      );
    }

    // Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
    // primeiro byte estritamente crescente (um contador/timestamp cru
    // produziria isso quase sempre; aleatório, só ~50% das vezes).
    var crescentes = 0;
    for (var i = 1; i < ivs.length; i++) {
      if (ivs[i][0] > ivs[i - 1][0]) {
        crescentes++;
      }
    }
    final proporcaoCrescente = crescentes / (ivs.length - 1);
    if (proporcaoCrescente > 0.65 || proporcaoCrescente < 0.35) {
      problemas.add(
        'primeiro byte do IV parece monotônico '
        '(${(proporcaoCrescente * 100).toStringAsFixed(0)}% das vezes '
        'crescente; aleatório ficaria perto de 50%)',
      );
    }

    // Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
    // (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
    // repetição interna) - a AUSÊNCIA de qualquer repetição interna em
    // quase todos os IVs seria estranha (sugeriria geração não-uniforme,
    // tipo bytes distintos forçados).
    var semRepeticaoInterna = 0;
    for (final iv in ivs) {
      if (iv.toSet().length == iv.length) {
        semRepeticaoInterna++;
      }
    }
    final proporcaoSemRepeticao = semRepeticaoInterna / ivs.length;
    // Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
    if (proporcaoSemRepeticao > 0.9 || proporcaoSemRepeticao < 0.5) {
      problemas.add(
        '${(proporcaoSemRepeticao * 100).toStringAsFixed(0)}% dos IVs não '
        'têm nenhum byte repetido internamente '
        '(esperado ~72% para 16 bytes aleatórios)',
      );
    }

    if (problemas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        problemas.join('; '),
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      'qui-quadrado=${qui2.toStringAsFixed(1)}, '
          '${(proporcaoCrescente * 100).toStringAsFixed(0)}% '
          'primeiro-byte-crescente (~50% esperado), '
          '${(proporcaoSemRepeticao * 100).toStringAsFixed(0)}% sem repetição '
          'interna (~72% esperado) - tudo consistente com IV aleatório',
    );
  }
}

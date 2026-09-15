// Runner de fuzzing cruzado: gera keystreams e checksums brutos a partir de
// fuzz/casos.txt para comparação com as demais implementações.
//
// uso: dart run bin/fuzz_cruzado.dart <entrada> <saida>

import 'dart:io';
import 'dart:typed_data';

import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/Util.dart';

void main(List<String> args) {
  if (args.length < 2) {
    stderr.writeln('uso: dart run bin/fuzz_cruzado.dart <entrada> <saida>');
    exit(1);
  }

  final linhas = File(args[0])
      .readAsLinesSync()
      .map((linha) => linha.trim())
      .where((linha) => linha.isNotEmpty)
      .toList();

  final alvo = CriptografiaAlvo();
  final saida = <String>[];

  for (var indice = 0; indice < linhas.length; indice++) {
    final partes = linhas[indice].split('|');
    if (partes.length < 4) {
      stderr.writeln('Linha malformada no índice $indice: ${linhas[indice]}');
      exit(1);
    }

    final chave = hexToBytes(partes[0]);
    final iv = hexToBytes(partes[1]);
    final proposito = partes[2];
    final plaintext =
        partes[3].isEmpty ? Uint8List(0) : hexToBytes(partes[3]);

    final ks = alvo.gerarKeystreamBruto(chave, iv, proposito, plaintext.length);
    final mac = alvo.checksumBruto(plaintext, chave);

    saida.add('$indice|${bytesToHex(ks)}|${bytesToHex(mac)}');
  }

  File(args[1]).writeAsStringSync('${saida.join('\n')}\n');
}

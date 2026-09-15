import 'dart:io';

import 'package:criptografia/Seguranca/Ataques/AtaqueAdulteracao.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueBytesFixos.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueChaveErrada.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueColisaoIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIdaEVolta.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueInteroperabilidade.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueValidacaoChave.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueVetorDeterministico.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/SuiteDeAtaques.dart';

/// Roda a suíte de ataques contra a implementação Dart da cifra.
void main() {
  final alvo = CriptografiaAlvo();

  final suite = SuiteDeAtaques();
  suite
      .adicionar(AtaqueIdaEVolta())
      .adicionar(AtaqueAdulteracao())
      .adicionar(AtaqueVetorDeterministico())
      .adicionar(AtaqueInteroperabilidade())
      .adicionar(AtaqueColisaoIV())
      .adicionar(AtaqueBytesFixos())
      .adicionar(AtaqueChaveErrada())
      .adicionar(AtaqueValidacaoChave());

  final passou = suite.rodarEImprimir(alvo);

  exit(passou ? 0 : 1);
}

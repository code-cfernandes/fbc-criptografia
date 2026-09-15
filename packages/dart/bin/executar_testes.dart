import 'dart:io';

import 'package:criptografia/Seguranca/Ataques/AtaqueAdulteracao.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAproximacaoLinear.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAutocorrelacao.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAvalanche.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAvalancheChave.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAvalancheChecksum.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueBateriaEstatistica.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueBIC.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueBytesFixos.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCanonicalizacaoToken.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueChaveErrada.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueChaveRelacionada.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueChavesDegeneradas.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueChavesFracas.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCiphertextEstatistico.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCoberturaDependencia.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCoberturaDependenciaIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueColisaoChecksum.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueColisaoIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueComplexidadeLinear.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueConfusaoCampos.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCorrelacaoPosicoes.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCusum.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueDiferencialKeystream.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueDistribuicaoBytes.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueDistribuicaoPorPosicao.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueEntropiaAproximada.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueEntropiaIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueFoldEstrutural.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIdaEVolta.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIdaEVoltaBinario.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIndependenciaProposito.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIntegral.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueInteroperabilidade.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIVsDegenerados.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueLengthExtension.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueLinearidadeChecksum.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueMac.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueMensagemLonga.dart';
import 'package:criptografia/Seguranca/Ataques/AtaquePreditorDeBits.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueReusoIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueRotacional.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueSAC.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueSeparacaoChaveIV.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueSerialBits.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueTiming.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueTokensMalformados.dart';
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
      .adicionar(AtaqueColisaoIV())
      .adicionar(AtaqueBytesFixos())
      .adicionar(AtaqueAvalanche())
      .adicionar(AtaqueDistribuicaoBytes())
      .adicionar(AtaqueFoldEstrutural())
      .adicionar(AtaqueCoberturaDependencia())
      .adicionar(AtaqueIVsDegenerados())
      .adicionar(AtaqueCorrelacaoMesmoPlaintext())
      .adicionar(AtaqueReusoIV())
      .adicionar(AtaqueVetorDeterministico())
      .adicionar(AtaqueTiming())
      .adicionar(AtaqueColisaoChecksum())
      .adicionar(AtaqueEntropiaIV())
      .adicionar(AtaqueAvalancheChave())
      .adicionar(AtaqueAvalancheChecksum())
      .adicionar(AtaqueIndependenciaProposito())
      .adicionar(AtaqueAutocorrelacao())
      .adicionar(AtaqueTokensMalformados())
      .adicionar(AtaqueChaveErrada())
      .adicionar(AtaqueComplexidadeLinear())
      .adicionar(AtaqueBateriaEstatistica())
      .adicionar(AtaqueCanonicalizacaoToken())
      .adicionar(AtaqueCoberturaDependenciaIV())
      .adicionar(AtaqueSeparacaoChaveIV())
      .adicionar(AtaqueChavesDegeneradas())
      .adicionar(AtaqueSerialBits())
      .adicionar(AtaqueCusum())
      .adicionar(AtaqueEntropiaAproximada())
      .adicionar(AtaqueMensagemLonga())
      .adicionar(AtaqueIdaEVoltaBinario())
      .adicionar(AtaqueConfusaoCampos())
      .adicionar(AtaqueLinearidadeChecksum())
      .adicionar(AtaqueValidacaoChave())
      .adicionar(AtaqueIntegral())
      .adicionar(AtaqueDiferencialKeystream())
      .adicionar(AtaqueDistribuicaoPorPosicao())
      .adicionar(AtaqueCorrelacaoPosicoes())
      .adicionar(AtaquePreditorDeBits())
      .adicionar(AtaqueInteroperabilidade())
      .adicionar(AtaqueSAC())
      .adicionar(AtaqueBIC())
      .adicionar(AtaqueChaveRelacionada())
      .adicionar(AtaqueRotacional())
      .adicionar(AtaqueChavesFracas())
      .adicionar(AtaqueAproximacaoLinear())
      .adicionar(AtaqueCiphertextEstatistico())
      .adicionar(AtaqueMac())
      .adicionar(AtaqueLengthExtension());

  final passou = suite.rodarEImprimir(alvo);

  exit(passou ? 0 : 1);
}

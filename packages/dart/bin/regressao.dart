import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:criptografia/Core/Criptografia.dart' as core;
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueAvalancheChecksum.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCanonicalizacaoToken.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueFoldEstrutural.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueIntegral.dart';
import 'package:criptografia/Seguranca/Ataques/AtaqueSeparacaoChaveIV.dart';
import 'package:criptografia/Seguranca/CriptografiaAlvo.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

// Harness de regressão histórica.
//
// Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
// bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
// (vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
// PRECISA resistir (vulneravel=false).

const int TAM_BLOCO = 32;
const String DIGITOS_PI =
    '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

int rotEsquerda8(int byte, int n) {
  n &= 7;
  if (n == 0) return byte & 0xFF;
  return ((byte << n) | (byte >> (8 - n))) & 0xFF;
}

int rotacaoDoRound(int roundIdx) {
  final d = int.parse(DIGITOS_PI[roundIdx % DIGITOS_PI.length]);
  return (d % 7) + 1;
}

// passo com mutações: bug 5 remove a reinserção da chave em cada rodada.
(int, int) passoComBug(
  int bug,
  int a,
  int b,
  Uint8List keyBuf,
  List<int> propositoBuf,
  int posFib,
  int roundIdx,
) {
  final n = rotacaoDoRound(roundIdx);
  var soma = (a + b) & 0xFF;
  soma = rotEsquerda8(soma, n);
  soma ^= propositoBuf[posFib % propositoBuf.length];
  if (bug != 5) {
    soma ^= keyBuf[(posFib + roundIdx) % keyBuf.length];
  }
  soma = (soma * 131) & 0xFF;
  return (b, soma);
}

// gerarKeystream com mutações: bugs 1, 2, 4, 5.
Uint8List gerarKeystreamComBug(
  int bug,
  Uint8List keyBuf,
  Uint8List ivBuf,
  String proposito,
  int tamanho,
) {
  if (bug == 1) {
    // bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
    return core.gerarKeystream(keyBuf, Uint8List(ivBuf.length), proposito, tamanho);
  }

  const bloco = TAM_BLOCO;
  // bug 2: o colapso de metades só acontece quando a distância é exatamente
  // metade do bloco (16) — reproduzimos a condição histórica.
  final distancias = bug == 4
      ? <int>[3]
      : bug == 2
      ? <int>[3, 5, 11, 19, 41, 16]
      : <int>[3, 5, 11, 19, 41, 3, 5, 11, 19, 41];
  final ivLen = ivBuf.length;
  final keyLen = keyBuf.length;
  final propositoBuf = utf8.encode(proposito);

  final a = Uint8List(bloco);
  var b = Uint8List(bloco);
  for (var pos = 0; pos < bloco; pos++) {
    a[pos] = keyBuf[pos % keyLen] ^ ivBuf[pos % ivLen];
    b[pos] = keyBuf[(pos + 1) % keyLen] ^ ivBuf[(pos + 1) % ivLen];
  }

  final partes = <Uint8List>[];
  var totalGerado = 0;
  var roundIdx = 0;
  var posFibBase = 0;

  while (totalGerado < tamanho) {
    for (final dist in distancias) {
      final novoB = Uint8List(bloco);
      for (var pos = 0; pos < bloco; pos++) {
        final (novoA, novoBb) = passoComBug(
          bug,
          a[pos],
          b[pos],
          keyBuf,
          propositoBuf,
          posFibBase + pos,
          roundIdx,
        );
        a[pos] = novoA;
        novoB[pos] = novoBb;
      }
      final misturado = Uint8List(bloco);
      for (var pos = 0; pos < bloco; pos++) {
        final vizinho = novoB[(pos + dist) % bloco];
        if (bug == 2) {
          // bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
          misturado[pos] = rotEsquerda8(novoB[pos] ^ vizinho, 1);
        } else {
          misturado[pos] = rotEsquerda8(novoB[pos], 1) ^ vizinho;
        }
      }
      b = misturado;
      roundIdx++;
    }
    posFibBase += bloco;
    partes.add(Uint8List.fromList(b));
    totalGerado += bloco;
  }

  final saida = Uint8List(tamanho);
  var offset = 0;
  for (final parte in partes) {
    if (offset >= tamanho) break;
    final n = min(parte.length, tamanho - offset);
    saida.setRange(offset, offset + n, parte);
    offset += n;
  }
  return saida;
}

// checksum com mutação: bug 3 remove a finalização.
Uint8List checksumComBug(int bug, Uint8List dadosBuf, Uint8List keyBuf) {
  final saida = Uint8List(32);
  final keyLen = keyBuf.length;
  final len = dadosBuf.length;

  for (var rodada = 0; rodada < 8; rodada++) {
    var acumulador = (0x811c9dc5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF;

    for (var i = 0; i < len; i++) {
      final byte = dadosBuf[i] ^ keyBuf[(i + rodada) % keyLen];
      acumulador = (acumulador ^ byte) & 0xFFFFFFFF;
      acumulador = (acumulador * 16777619) & 0xFFFFFFFF;
      acumulador = core.rotEsquerda32(acumulador, (i % 13) + 1);
    }

    if (bug != 3) {
      for (var k = 0; k < 3; k++) {
        acumulador = (acumulador ^ (acumulador >> 16)) & 0xFFFFFFFF;
        acumulador = (acumulador * 16777619) & 0xFFFFFFFF;
        acumulador = core.rotEsquerda32(acumulador, 13);
      }
    }

    saida[rodada * 4 + 0] = (acumulador >> 24) & 0xFF;
    saida[rodada * 4 + 1] = (acumulador >> 16) & 0xFF;
    saida[rodada * 4 + 2] = (acumulador >> 8) & 0xFF;
    saida[rodada * 4 + 3] = acumulador & 0xFF;
  }

  return saida;
}

// base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo.
Uint8List base64urlDecodeComBug(int bug, String str) {
  if (bug != 6) {
    return core.base64urlDecode(str);
  }
  var s = str
      .replaceAll('-', '+')
      .replaceAll('_', '/')
      .replaceAll(RegExp(r'[^A-Za-z0-9+/=]'), '');
  final mod = s.length % 4;
  if (mod != 0) {
    s += '=' * (4 - mod);
  }
  return Uint8List.fromList(base64.decode(s));
}

Uint8List _concatenar(List<Uint8List> partes) {
  var total = 0;
  for (final p in partes) {
    total += p.length;
  }
  final out = Uint8List(total);
  var offset = 0;
  for (final p in partes) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}

bool _iguais(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Alvo que aponta para a cifra com o bug selecionado.
class SnapshotAlvo extends CriptografiaAlvo {
  final int bug;

  SnapshotAlvo(this.bug) : super();

  @override
  Uint8List gerarKeystreamBruto(
    Object key,
    Object iv,
    String proposito,
    int tamanho,
  ) {
    final keyBuf = key is String
        ? Uint8List.fromList(toBytes(key))
        : toBytes(key);
    final ivBuf = toBytes(iv);
    return gerarKeystreamComBug(bug, keyBuf, ivBuf, proposito, tamanho);
  }

  @override
  Uint8List checksumBruto(Object dados, Object key) {
    return checksumComBug(bug, toBytes(dados), toBytes(key));
  }

  @override
  Uint8List base64urlDecode(String data) => base64urlDecodeComBug(bug, data);

  @override
  String encrypt(Object texto) {
    final key = Uint8List.fromList(utf8.encode(chaveDeTeste()));
    final iv = core.randomBytes(16);
    final textBuf = toBytes(texto);
    final ks = gerarKeystreamBruto(key, iv, 'enc', textBuf.length);
    final ct = Uint8List(textBuf.length);
    for (var i = 0; i < textBuf.length; i++) {
      ct[i] = textBuf[i] ^ ks[i];
    }
    final macKey = gerarKeystreamBruto(key, iv, 'mac', 32);
    final integridade = checksumBruto(_concatenar([iv, ct]), macKey);
    return 'FBC${core.base64urlEncode(_concatenar([integridade, ct, iv]))}';
  }

  @override
  String decrypt(String token) {
    if (token.length < 3 || token.substring(0, 3) != 'FBC') {
      throw const FormatException('Invalid text. Text must start with FBC.');
    }
    final key = Uint8List.fromList(utf8.encode(chaveDeTeste()));
    final decoded = base64urlDecode(token.substring(3));
    final integ = decoded.sublist(0, 32);
    final iv = decoded.sublist(decoded.length - 16);
    final ct = decoded.sublist(32, decoded.length - 16);
    final macKey = gerarKeystreamBruto(key, iv, 'mac', 32);
    final esperado = checksumBruto(_concatenar([iv, ct]), macKey);
    if (!_iguais(esperado, integ)) {
      throw const FormatException('Token adulterado ou chave incorreta.');
    }
    final ks = gerarKeystreamBruto(key, iv, 'enc', ct.length);
    final out = Uint8List(ct.length);
    for (var i = 0; i < ct.length; i++) {
      out[i] = ct[i] ^ ks[i];
    }
    return utf8.decode(out, allowMalformed: true);
  }
}

class CasoRegressao {
  final int bug;
  final String descricao;
  final Ataque ataque;

  CasoRegressao(this.bug, this.descricao, this.ataque);
}

final casos = <CasoRegressao>[
  CasoRegressao(
    1,
    'keystream ignora o IV',
    AtaqueCorrelacaoMesmoPlaintext(),
  ),
  CasoRegressao(
    2,
    'combinador simétrico (metades colapsam)',
    AtaqueFoldEstrutural(),
  ),
  CasoRegressao(3, 'checksum sem finalização', AtaqueAvalancheChecksum()),
  CasoRegressao(4, 'cinco rodadas de difusão', AtaqueIntegral()),
  CasoRegressao(5, 'chave só no estado inicial', AtaqueSeparacaoChaveIV()),
  CasoRegressao(6, 'base64 não estrito', AtaqueCanonicalizacaoToken()),
];

void main() {
  print('=' * 72);
  print('REGRESSÃO HISTÓRICA');
  print('=' * 72);

  var falhas = 0;
  for (final caso in casos) {
    final snapshot = SnapshotAlvo(caso.bug);
    final real = CriptografiaAlvo();

    ResultadoAtaque rSnapshot;
    ResultadoAtaque rReal;
    try {
      rSnapshot = caso.ataque.executar(snapshot);
      rReal = caso.ataque.executar(real);
    } catch (e) {
      print('  ❌ bug ${caso.bug} (${caso.descricao}): erro — $e');
      falhas++;
      continue;
    }

    final detectou = rSnapshot.vulneravel == true;
    final resistiu = rReal.vulneravel == false;
    final ok = detectou && resistiu;
    if (!ok) falhas++;

    print(
      '  ${ok ? '✅' : '❌'} bug ${caso.bug} (${caso.descricao}): '
      'snapshot ${detectou ? 'detectado' : 'NÃO detectado'} | '
      'atual ${resistiu ? 'resistiu' : 'ACUSOU'}',
    );
    if (!ok) {
      print('       snapshot: ${rSnapshot.linhaResumo()}');
      print('       atual:    ${rReal.linhaResumo()}');
    }
  }

  print('=' * 72);
  if (falhas == 0) {
    print(
      'RESUMO: ${casos.length} bugs históricos detectados; '
      'código atual resiste a todos.',
    );
  } else {
    print('RESUMO: $falhas caso(s) falharam.');
  }
  print('=' * 72);

  exit(falhas == 0 ? 0 : 1);
}

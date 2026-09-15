/// Cifra caseira educacional — porte de Criptografia.php.
///
/// Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
///
/// Ver Criptografia.php para os comentários completos sobre o design
/// (difusão tipo butterfly, distâncias Fibonacci->primo, rotação via Pi).
/// Este arquivo replica a lógica byte a byte, sem "melhorias" - qualquer
/// mudança de comportamento aqui quebraria compatibilidade com tokens
/// gerados pelas outras versões.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

const int TAM_BLOCO = 32;

// Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
const List<int> DISTANCIAS_DIFUSAO = [
  3,
  5,
  11,
  19,
  41,
  3,
  5,
  11,
  19,
  41,
]; // dobrado pra combater ataque integral

const String DIGITOS_PI =
    '31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679';

int rotEsquerda8(int byte, int n) {
  n &= 7;
  if (n == 0) return byte & 0xFF;
  return ((byte << n) | (byte >> (8 - n))) & 0xFF;
}

int rotEsquerda32(int val, int n) {
  n &= 31;
  val &= 0xFFFFFFFF;
  if (n == 0) return val;
  return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF;
}

int rotacaoDoRound(int roundIdx) {
  final d = int.parse(DIGITOS_PI[roundIdx % DIGITOS_PI.length]);
  return (d % 7) + 1;
}

/// Um passo da recorrência tipo-Fibonacci pra uma posição do bloco.
(int, int) passo(
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
  // A chave participa de CADA rodada, não só do estado inicial (ver
  // comentário equivalente em Criptografia.php sobre keystream(key,iv) ==
  // keystream(key^D, iv^D16) sem isso).
  soma ^= keyBuf[(posFib + roundIdx) % keyBuf.length];
  soma = (soma * 131) & 0xFF;

  return (b, soma); // novo a = b antigo; novo b = soma
}

/// Gera `tamanho` bytes de keystream a partir de KEY + IV + propósito.
Uint8List gerarKeystream(
  Uint8List keyBuf,
  Uint8List ivBuf,
  String proposito,
  int tamanho,
) {
  const bloco = TAM_BLOCO;
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
    for (final dist in DISTANCIAS_DIFUSAO) {
      final novoB = Uint8List(bloco);
      for (var pos = 0; pos < bloco; pos++) {
        final (novoA, novoBb) = passo(
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

      // Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR
      // (ver comentário equivalente em Criptografia.php sobre por que isso
      // é essencial - combinação simétrica colapsa metades do bloco).
      final misturado = Uint8List(bloco);
      for (var pos = 0; pos < bloco; pos++) {
        final vizinho = novoB[(pos + dist) % bloco];
        misturado[pos] = rotEsquerda8(novoB[pos], 1) ^ vizinho;
      }
      b = misturado;
      roundIdx++;
    }

    posFibBase += bloco;
    partes.add(b);
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

Uint8List xorBytes(Uint8List dadosBuf, Uint8List keystreamBuf) {
  final out = Uint8List(dadosBuf.length);
  for (var i = 0; i < dadosBuf.length; i++) {
    out[i] = dadosBuf[i] ^ keystreamBuf[i];
  }
  return out;
}

/// "MAC" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes.
Uint8List checksum(Uint8List dadosBuf, Uint8List keyBuf) {
  final saida = Uint8List(32);
  final keyLen = keyBuf.length;
  final len = dadosBuf.length;

  for (var rodada = 0; rodada < 8; rodada++) {
    var acumulador = (0x811c9dc5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF;

    for (var i = 0; i < len; i++) {
      final byte = dadosBuf[i] ^ keyBuf[(i + rodada) % keyLen];
      acumulador = (acumulador ^ byte) & 0xFFFFFFFF;
      acumulador = (acumulador * 16777619) & 0xFFFFFFFF;
      acumulador = rotEsquerda32(acumulador, (i % 13) + 1);
    }

    // Finalização: sem isso, o último byte processado só passa por 1
    // multiply+rotate antes de virar saída, e sofre avalanche fraca
    // (medido ~25-30% em vez de ~50% nos últimos bytes do bloco de dados).
    for (var k = 0; k < 3; k++) {
      acumulador = (acumulador ^ (acumulador >> 16)) & 0xFFFFFFFF;
      acumulador = (acumulador * 16777619) & 0xFFFFFFFF;
      acumulador = rotEsquerda32(acumulador, 13);
    }

    saida[rodada * 4 + 0] = (acumulador >> 24) & 0xFF;
    saida[rodada * 4 + 1] = (acumulador >> 16) & 0xFF;
    saida[rodada * 4 + 2] = (acumulador >> 8) & 0xFF;
    saida[rodada * 4 + 3] = acumulador & 0xFF;
  }

  return saida;
}

String base64urlEncode(Uint8List buf) {
  return base64Url.encode(buf).replaceAll('=', '');
}

Uint8List base64urlDecode(String str) {
  if (str.isNotEmpty && !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(str)) {
    throw const FormatException('Token contém caracteres inválidos.');
  }

  var s = str.replaceAll('-', '+').replaceAll('_', '/');
  final mod = s.length % 4;
  if (mod == 1) {
    throw const FormatException('Comprimento de token inválido.');
  }
  if (mod != 0) {
    s += '=' * (4 - mod);
  }

  final bytes = Uint8List.fromList(base64.decode(s));

  // Canonicidade: reencoda e compara - pega tanto caracteres que o decoder
  // ignoraria silenciosamente quanto bits não-canônicos no último grupo.
  if (base64urlEncode(bytes) != str) {
    throw const FormatException('Token não está em forma canônica.');
  }

  return bytes;
}

/// Chave usada nos testes. Quando `null`, cai para `Platform.environment`.
///
/// O ambiente do processo Dart não é mutável em tempo de execução, então a
/// suíte usa este override para os ataques que trocam de chave. O padrão
/// continua sendo a variável `FBC_KEY`.
String? _chaveOverride;

void definirChave(String? chave) {
  _chaveOverride = chave;
}

Uint8List getKey() {
  final chave = _chaveOverride ?? Platform.environment['FBC_KEY'];
  if (chave == null || utf8.encode(chave).length != 32) {
    throw StateError('Chave deve ter 32 bytes.');
  }
  return Uint8List.fromList(utf8.encode(chave));
}

Uint8List _paraBytes(Object texto) {
  if (texto is String) {
    return Uint8List.fromList(utf8.encode(texto));
  }
  if (texto is Uint8List) {
    return texto;
  }
  if (texto is List<int>) {
    return Uint8List.fromList(texto);
  }
  throw ArgumentError('Texto deve ser String ou bytes.');
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

bool _compararConstante(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List randomBytes(int n) {
  final random = Random.secure();
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = random.nextInt(256);
  }
  return out;
}

String encrypt(Object texto) {
  final key = getKey();
  final iv = randomBytes(16);
  final textBuf = _paraBytes(texto);

  final encKeystream = gerarKeystream(key, iv, 'enc', textBuf.length);
  final ciphertext = xorBytes(textBuf, encKeystream);

  final macKey = gerarKeystream(key, iv, 'mac', TAM_BLOCO);
  final integridade = checksum(_concatenar([iv, ciphertext]), macKey);

  return 'FBC' + base64urlEncode(_concatenar([integridade, ciphertext, iv]));
}

String decrypt(String text) {
  if (text.length < 3 || text.substring(0, 3) != 'FBC') {
    throw const FormatException('Invalid text. Text must start with FBC.');
  }

  final key = getKey();
  final decoded = base64urlDecode(text.substring(3));

  if (decoded.length < TAM_BLOCO + 16) {
    throw const FormatException('Token curto demais.');
  }

  final integridadeRecebida = decoded.sublist(0, TAM_BLOCO);
  final iv = decoded.sublist(decoded.length - 16);
  final ciphertext = decoded.sublist(TAM_BLOCO, decoded.length - 16);

  final macKey = gerarKeystream(key, iv, 'mac', TAM_BLOCO);
  final integridadeEsperada = checksum(_concatenar([iv, ciphertext]), macKey);

  if (!_compararConstante(integridadeEsperada, integridadeRecebida)) {
    throw const FormatException('Token adulterado ou chave incorreta.');
  }

  final encKeystream = gerarKeystream(key, iv, 'enc', ciphertext.length);
  // allowMalformed replica o `Buffer.toString('utf8')` do Node e o
  // `String::from_utf8_lossy` do Rust: bytes inválidos viram U+FFFD em vez de
  // lançar. Sem isso, dados binários arbitrários não sobrevivem à ida-e-volta
  // (os ataques AtaqueIdaEVoltaBinario e AtaqueMensagemLonga dependem disso).
  return utf8.decode(xorBytes(ciphertext, encKeystream), allowMalformed: true);
}

import 'dart:math';
import 'dart:typed_data';

/// Inteiro aleatório em [min, max], inclusivo (equivalente ao random_int do PHP).
int randomInt(int min, int max) {
  return min + Random.secure().nextInt(max - min + 1);
}

/// N bytes aleatórios (equivalente ao random_bytes do PHP).
Uint8List randomBytes(int n) {
  final random = Random.secure();
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = random.nextInt(256);
  }
  return out;
}

/// Converte string (binária/utf8) ou bytes para Uint8List.
Uint8List toBytes(Object value) {
  if (value is Uint8List) return value;
  if (value is List<int>) return Uint8List.fromList(value);
  if (value is String) {
    return Uint8List.fromList(value.codeUnits.map((c) => c & 0xFF).toList());
  }
  throw ArgumentError('Valor deve ser String ou bytes.');
}

/// Repete uma string `n` vezes (o `'x'.repeat(n)` do JS).
String repetir(String s, int n) {
  return List<String>.filled(n, s).join();
}

/// Representação hexadecimal minúscula de bytes.
String bytesToHex(List<int> bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write((b & 0xFF).toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// Converte uma string hexadecimal em bytes.
Uint8List hexToBytes(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Conta quantos bits diferem entre dois buffers/strings de mesmo tamanho.
int bitsDiferentes(Object a, Object b) {
  final A = toBytes(a);
  final B = toBytes(b);
  final len = min(A.length, B.length);
  var diff = 0;
  for (var i = 0; i < len; i++) {
    diff += contarBits1(A[i] ^ B[i]);
  }
  return diff;
}

/// Popcount de um byte (0-255).
int contarBits1(int byte) {
  var x = byte & 0xFF;
  var count = 0;
  while (x != 0) {
    count += x & 1;
    x >>= 1;
  }
  return count;
}

/// Popcount total de um buffer.
int contarBitsBuffer(List<int> buf) {
  var total = 0;
  for (var i = 0; i < buf.length; i++) {
    total += contarBits1(buf[i]);
  }
  return total;
}

/// Fisher-Yates: embaralha uma cópia do array.
List<T> shuffle<T>(List<T> array) {
  final out = List<T>.from(array);
  for (var i = out.length - 1; i > 0; i--) {
    final j = randomInt(0, i);
    final tmp = out[i];
    out[i] = out[j];
    out[j] = tmp;
  }
  return out;
}

/// Chave aleatória de um mapa (equivalente ao array_rand do PHP).
K arrayRandKey<K, V>(Map<K, V> obj) {
  final keys = obj.keys.toList();
  return keys[randomInt(0, keys.length - 1)];
}

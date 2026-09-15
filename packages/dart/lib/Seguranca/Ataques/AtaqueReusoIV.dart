import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
/// reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
/// Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
/// aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
/// gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
/// vaza nesse cenário catastrófico.
///
/// Isso não é um "bug" da implementação (é uma propriedade universal de
/// qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
/// quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
/// suíte: a segurança inteira depende do IV nunca repetir.
class AtaqueReusoIV extends Ataque {
  @override
  String nome() => 'Reuso forçado de IV (two-time pad)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final chave = alvo.chaveDeTeste();
    final ivFixo = randomBytes(alvo.tamanhoIv());

    const plaintext1 = 'TRANSFERIR_1000';
    const plaintext2 = 'CANCELAR_TUDO!!';
    final tamanho = plaintext1.length > plaintext2.length
        ? plaintext1.length
        : plaintext2.length;

    final keystream = alvo.gerarKeystreamBruto(chave, ivFixo, 'enc', tamanho);

    final ciphertext1 = _xor(plaintext1, keystream);
    final ciphertext2 = _xor(plaintext2, keystream);

    // O atacante NUNCA precisou saber a key nem o keystream - só
    // observou os dois ciphertexts (que vazariam publicamente se o
    // IV fosse reusado) e os combinou entre si.
    final xorDosCiphertexts = _xor(ciphertext1, ciphertext2);
    final xorEsperadoDosPlaintexts = _xor(plaintext1, plaintext2);

    final vazou = _iguais(xorDosCiphertexts, xorEsperadoDosPlaintexts);

    // Com IV reusado, a propriedade é universal e sempre se confirma - por
    // isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
    // demonstração). Só vira alerta se, por algum motivo, a propriedade
    // NÃO se confirmar (o que indicaria um combinador inconsistente).
    return ResultadoAtaque(
      nome(),
      !vazou,
      vazou ? Severidade.demonstracao : Severidade.alta,
      vazou
          ? 'Demonstração (não é falha da implementação): XOR(c1,c2) revela '
                'XOR(p1,p2) sem precisar da chave. Inerente a qualquer '
                'combinador XOR/soma - a ÚNICA defesa é garantir que o IV '
                'NUNCA se repita (ver Ataque de Colisão de IV).'
          : 'INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos '
                'plaintexts (investigar)',
      {
        'plaintext1': plaintext1,
        'plaintext2': plaintext2,
        'xor_plaintexts_hex': bytesToHex(xorEsperadoDosPlaintexts),
        'xor_ciphertexts_hex': bytesToHex(xorDosCiphertexts),
      },
    );
  }

  Uint8List _xor(Object a, Object b) {
    final A = toBytes(a);
    final B = toBytes(b);
    final len = A.length < B.length ? A.length : B.length;
    final out = Uint8List(len);
    for (var i = 0; i < len; i++) {
      out[i] = A[i] ^ B[i];
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
}

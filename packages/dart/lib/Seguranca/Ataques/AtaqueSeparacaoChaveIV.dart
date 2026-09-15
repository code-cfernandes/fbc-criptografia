import 'dart:typed_data';

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
/// Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
/// resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
///
///     keystream(key, iv) == keystream(key ^ d, iv ^ d)
///
/// para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
/// propriedade estrutural relevante: significa que key e iv não entram de
/// forma independente na cifra, o que enfraquece o modelo de segurança (o IV
/// deveria contribuir com entropia própria, não só deslocar a chave por XOR).
class AtaqueSeparacaoChaveIV extends Ataque {
  final int _tentativas;
  final int _tamanhoBloco;

  AtaqueSeparacaoChaveIV({int tentativas = 50, int tamanhoBloco = 32})
    : _tentativas = tentativas,
      _tamanhoBloco = tamanhoBloco;

  @override
  String nome() => 'Separação chave/IV (invariância a key XOR iv)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final tamChave = toBytes(alvo.chaveDeTeste()).length;
    final tamIv = alvo.tamanhoIv();

    var confirmacoes = 0;
    for (var t = 0; t < _tentativas; t++) {
      final chave = randomBytes(tamChave);
      final iv = randomBytes(tamIv);
      final d = randomBytes(tamIv);

      final chave2 = Uint8List(tamChave);
      for (var p = 0; p < tamChave; p++) {
        chave2[p] = chave[p] ^ d[p % tamIv];
      }
      final iv2 = Uint8List(tamIv);
      for (var p = 0; p < tamIv; p++) {
        iv2[p] = iv[p] ^ d[p];
      }

      final ks1 = alvo.gerarKeystreamBruto(chave, iv, 'enc', _tamanhoBloco);
      final ks2 = alvo.gerarKeystreamBruto(chave2, iv2, 'enc', _tamanhoBloco);

      if (_iguais(ks1, ks2)) {
        confirmacoes++;
      }
    }

    final invariante = confirmacoes == _tentativas;

    return ResultadoAtaque(
      nome(),
      invariante,
      invariante ? Severidade.media : Severidade.info,
      invariante
          ? 'Confirmado em $_tentativas/$_tentativas: '
                'keystream(key,iv) == keystream(key^d, iv^d). '
                'O IV só desloca a chave por XOR antes da difusão - não '
                'injeta entropia independente no key schedule.'
          : 'Invariância não se confirmou ($confirmacoes/$_tentativas); '
                'key e iv entram de forma independente.',
      {'confirmacoes': confirmacoes, 'tentativas': _tentativas},
    );
  }

  bool _iguais(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/Util.dart';

/// Vetores de referência (Known Answer Tests) e interoperabilidade.
///
/// A mesma cifra é implementada em PHP, Node, TypeScript, Python, Bash e Dart.
/// Este ataque fixa keystreams e tokens conhecidos: se QUALQUER implementação
/// divergir, ela não reproduz estes valores e o ataque acusa.
///
/// Os tokens foram gerados com a chave de teste padrão
/// ('pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf'); o IV é aleatório, mas fica embutido no
/// token, então a decifragem é determinística.
const String CHAVE_FIXA = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

class _VetorKeystream {
  final String iv;
  final String proposito;
  final int tamanho;
  final String esperado;

  const _VetorKeystream(this.iv, this.proposito, this.tamanho, this.esperado);
}

const List<_VetorKeystream> _VETORES = [
  _VetorKeystream(
    '00000000000000000000000000000000',
    'enc',
    32,
    '219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249',
  ),
  _VetorKeystream(
    '00000000000000000000000000000000',
    'enc',
    64,
    '219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249'
        'a9b8fa2ec5a08abdae48729fe50aa1def4d6af963ecb11a46d1a4604046741a7',
  ),
  _VetorKeystream(
    '00000000000000000000000000000000',
    'mac',
    32,
    'ebaec6df127deb7dac57d584f86a13c53cfc74974da9f6594fd831acf3d07bb1',
  ),
  _VetorKeystream(
    '000102030405060708090a0b0c0d0e0f',
    'enc',
    32,
    '0c8c9ba9ee81e6b9d00bd84b22c4180afd2a0c595f35a6be05b9d0a3ba37baf9',
  ),
  _VetorKeystream(
    '000102030405060708090a0b0c0d0e0f',
    'mac',
    64,
    '2173c8774d071e983d895aeaa0cc2dd22d5da18b8427a98ee9ad89297eb03e0e'
        '961303b58b65bf2b6f48b7cfb2a04b1a7a9406f8a45605a1774d6fb8ddeda30d',
  ),
  _VetorKeystream(
    'ffffffffffffffffffffffffffffffff',
    'enc',
    32,
    'c2e2551794dea9cd8904550745adcc28baaf0179773eb0db171dc77701edae28',
  ),
  _VetorKeystream(
    '30313233343536373839616263646566',
    'enc',
    64,
    'ca36c5f105ea153f4dc6a591e97f7098bbc7c3aef2491423d9fb2ce612c84b72'
        '32009cb847d44cd2f72b47d0a293dd6227b96ce6cd2ba825e951b98e12819c0c',
  ),
  _VetorKeystream(
    '30313233343536373839616263646566',
    'mac',
    32,
    '22aec48f7ec4731e402cc64a1b31955d7757c75c5ce606e28eb47c8ad936af3f',
  ),
];

class _VetorToken {
  final String texto;
  final String token;

  const _VetorToken(this.texto, this.token);
}

const List<_VetorToken> _TOKENS = [
  _VetorToken(
    '',
    'FBCbBmERldK0rQ3SAu1PxJ7drr2ie-jwhDLefEaGiBsJ_2autyPG4oSs6DXEM_w6-6x',
  ),
  _VetorToken(
    'A',
    'FBCo5OnvHbHG6nILqXCjGzVYo32jIC9I_PAqQ9CvRxggyiYKwhedK4ynN65_SSrE_mezQ',
  ),
  _VetorToken(
    'TESTE',
    'FBCn7T3VBZFYnvG41Dx4VYn-tyKKd3QheLJ1kw7oDb9EhSUEfnTtlEN2Rxp1xaskppvmGSmeTI',
  ),
  _VetorToken(
    'mensagem de interoperabilidade entre linguagens',
    'FBCqgHvQ_SGLjte-SDNMHt3LyNB8qGUfMxn_N1PqWGdQmyE4iHtA3k45aAygQnBpqAXYxlwIx'
        'kDumz3ln33vAttxUwIuYExCrG-LaYLBUVEyuX49X86mScMpOd3isnqYhU',
  ),
];

class AtaqueInteroperabilidade extends Ataque {
  @override
  String nome() => 'Interoperabilidade e vetores conhecidos (KAT)';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    final falhas = <String>[];

    for (final v in _VETORES) {
      final ks = alvo.gerarKeystreamBruto(
        CHAVE_FIXA,
        hexToBytes(v.iv),
        v.proposito,
        v.tamanho,
      );
      if (bytesToHex(ks) != v.esperado) {
        falhas.add('keystream iv=${v.iv} prop=${v.proposito} tam=${v.tamanho}');
      }
    }

    for (final t in _TOKENS) {
      try {
        if (alvo.decrypt(t.token) != t.texto) {
          falhas.add('token não decifrou para "${t.texto}"');
        }
      } catch (_) {
        falhas.add('token rejeitado: "${t.texto}"');
      }
    }

    if (falhas.isNotEmpty) {
      return ResultadoAtaque(
        nome(),
        true,
        Severidade.alta,
        '${falhas.length} divergência(s) de interoperabilidade: '
            '${falhas.take(5).join('; ')}',
        {'falhas': falhas},
      );
    }

    return ResultadoAtaque(
      nome(),
      false,
      Severidade.info,
      '${_VETORES.length} vetores de keystream e ${_TOKENS.length} tokens de '
          'referência conferem',
    );
  }
}

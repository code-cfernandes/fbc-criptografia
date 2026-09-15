'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');

/**
 * Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico -
 * chamar a função duas vezes com a mesma entrada tem que dar o mesmo
 * resultado, sempre. Se não der, alguma fonte de aleatoriedade (relógio,
 * random_bytes, uniqid, etc.) vazou pra dentro de uma função que deveria
 * ser pura - isso quebraria o decrypt() em produção de forma intermitente
 * e seria um pesadelo de debugar.
 *
 * De brinde, esse ataque imprime o "vetor de referência" (Known Answer
 * Vector) pra esse par key/iv - guarde esse valor: se ele mudar entre
 * versões do código sem você ter mexido de propósito na lógica de mistura,
 * é sinal de uma regressão acidental.
 */
class AtaqueVetorDeterministico {
  nome() {
    return 'Determinismo (vetor de referência key/iv fixos)';
  }

  executar(alvo) {
    const chaveFixa = 'K'.repeat(Buffer.byteLength(alvo.chaveDeTeste(), 'utf8')); // chave fixa e conhecida
    const ivFixo = Buffer.alloc(alvo.tamanhoIv()); // IV fixo (só pra este teste)

    const ks1 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);
    if (ks1 == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }
    const ks2 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);
    const ks3 = alvo.gerarKeystreamBruto(chaveFixa, ivFixo, 'enc', 32);

    const deterministico = ks1.equals(ks2) && ks2.equals(ks3);

    return new ResultadoAtaque(
      this.nome(),
      !deterministico,
      deterministico ? 'info' : 'critica',
      deterministico
        ? 'Determinístico em 3 chamadas. Vetor de referência (key=64x"K", iv=zeros, prop=enc, 32 bytes): ' +
          ks1.toString('hex')
        : 'NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: ' +
          ks1.toString('hex') +
          ' / ' +
          ks2.toString('hex') +
          ' / ' +
          ks3.toString('hex'),
      { vetor_hex: ks1.toString('hex') },
    );
  }
}

module.exports = AtaqueVetorDeterministico;

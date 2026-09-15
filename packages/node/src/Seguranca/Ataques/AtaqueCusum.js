'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
 * passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
 * pequeno que o monobit quase não vê faz o desvio acumulado crescer.
 * Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
 */
class AtaqueCusum {
  constructor({ tamanho = 8192, limiteZ = 4.0 } = {}) {
    this.tamanho = tamanho;
    this.limiteZ = limiteZ;
  }

  nome() {
    return 'Somas cumulativas (cusum)';
  }

  executar(alvo) {
    const ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanho,
    );
    if (ks === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    let soma = 0;
    let maxAbs = 0;
    for (let i = 0; i < ks.length; i++) {
      const byte = ks[i];
      for (let b = 7; b >= 0; b--) {
        soma += ((byte >> b) & 1) === 1 ? 1 : -1;
        maxAbs = Math.max(maxAbs, Math.abs(soma));
      }
    }
    const n = ks.length * 8;
    const z = maxAbs / Math.sqrt(n);
    const vulneravel = z > this.limiteZ;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `max|S|=${maxAbs} sobre ${n} bits, max|S|/sqrt(n)=${z.toFixed(2)} (limite=${this.limiteZ.toFixed(1)})`,
      { max_abs: maxAbs, z },
    );
  }
}

module.exports = AtaqueCusum;

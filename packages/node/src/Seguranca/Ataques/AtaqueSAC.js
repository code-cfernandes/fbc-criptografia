'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
 * esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
 * bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
 */
class AtaqueSAC {
  constructor({ tamanhoBloco = 32, amostras = 40, tolerancia = 0.05 } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.amostras = amostras;
    this.tolerancia = tolerancia;
  }

  nome() {
    return 'SAC (Strict Avalanche Criterion)';
  }

  executar(alvo) {
    const chave = Buffer.from(alvo.chaveDeTeste(), 'utf8');
    const totalBits = this.tamanhoBloco * 8;
    const flips = new Array(totalBits).fill(0);
    const tamanhoIv = alvo.tamanhoIv();
    let total = 0;

    for (let pos = 0; pos < tamanhoIv; pos++) {
      for (let bit = 0; bit < 8; bit++) {
        for (let s = 0; s < this.amostras; s++) {
          const iv1 = randomBytes(tamanhoIv);
          const iv2 = Buffer.from(iv1);
          iv2[pos] = iv2[pos] ^ (1 << bit);

          const ks1 = alvo.gerarKeystreamBruto(chave, iv1, 'enc', this.tamanhoBloco);
          if (ks1 == null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
          }
          const ks2 = alvo.gerarKeystreamBruto(chave, iv2, 'enc', this.tamanhoBloco);

          for (let j = 0; j < totalBits; j++) {
            const b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
            const b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
            if (b1 !== b2) {
              flips[j]++;
            }
          }
          total++;
        }
      }
    }

    let pior = -1;
    let piorDesvio = 0;
    let piorP = 0.5;
    for (let j = 0; j < totalBits; j++) {
      const p = flips[j] / total;
      const desvio = Math.abs(p - 0.5);
      if (desvio > piorDesvio) {
        piorDesvio = desvio;
        pior = j;
        piorP = p;
      }
    }

    const vulneravel = piorDesvio > this.tolerancia;
    const detalhes =
      `pior bit de saída=${pior}: p=${(piorP * 100).toFixed(2)}% ` +
      `(esperado 50%, tolerância ±${(this.tolerancia * 100).toFixed(1)}%); ` +
      `${total} amostras por bit de entrada`;

    return new ResultadoAtaque(this.nome(), vulneravel, vulneravel ? 'alta' : 'info', detalhes, {
      pior,
      pior_p: piorP,
      desvio: piorDesvio,
    });
  }
}

module.exports = AtaqueSAC;

'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Aproximação linear (criptoanálise de Matsui): procura por correlação entre
 * bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
 * aproximação linear com viés relevante; bias alto é uma pista explorável.
 */
class AtaqueAproximacaoLinear {
  constructor({ amostras = 200, tamanhoBloco = 32, limiteBias = 0.3 } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
    this.limiteBias = limiteBias;
  }

  nome() {
    return 'Aproximação linear (viés de Walsh)';
  }

  executar(alvo) {
    const tamIv = alvo.tamanhoIv();
    const bitsEntrada = tamIv * 8;
    const bitsSaida = this.tamanhoBloco * 8;

    const entradas = [];
    const saidas = [];

    for (let s = 0; s < this.amostras; s++) {
      const chave = randomBytes(Buffer.byteLength(alvo.chaveDeTeste(), 'utf8'));
      const iv = randomBytes(tamIv);
      const ks = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);
      if (ks == null) {
        throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
      }

      const inBits = new Uint8Array(bitsEntrada);
      for (let j = 0; j < bitsEntrada; j++) {
        inBits[j] = (iv[j >> 3] >> (7 - (j & 7))) & 1;
      }
      const outBits = new Uint8Array(bitsSaida);
      for (let j = 0; j < bitsSaida; j++) {
        outBits[j] = (ks[j >> 3] >> (7 - (j & 7))) & 1;
      }
      entradas.push(inBits);
      saidas.push(outBits);
    }

    let maiorBias = 0;
    let par = [-1, -1];
    for (let i = 0; i < bitsEntrada; i++) {
      for (let j = 0; j < bitsSaida; j++) {
        let iguais = 0;
        for (let s = 0; s < this.amostras; s++) {
          if (entradas[s][i] === saidas[s][j]) iguais++;
        }
        const bias = Math.abs(iguais / this.amostras - 0.5);
        if (bias > maiorBias) {
          maiorBias = bias;
          par = [i, j];
        }
      }
    }

    const vulneravel = maiorBias > this.limiteBias;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `maior viés |p-0.5|=${maiorBias.toFixed(4)} na aproximação ` +
        `IV[bit ${par[0]}] -> saída[bit ${par[1]}] (limite ${this.limiteBias}); ` +
        `${this.amostras} amostras`,
      { maior_bias: maiorBias, par },
    );
  }
}

module.exports = AtaqueAproximacaoLinear;

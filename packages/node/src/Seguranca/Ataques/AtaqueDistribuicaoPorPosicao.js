'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
 * bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
 * soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
 */
class AtaqueDistribuicaoPorPosicao {
  constructor({ amostrasDeBlocos = 2000, tamanhoBloco = 32 } = {}) {
    this.amostrasDeBlocos = amostrasDeBlocos;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome() {
    return 'Distribuição de bytes por posição do bloco';
  }

  executar(alvo) {
    const chave = alvo.chaveDeTeste();
    const primeiro = alvo.gerarKeystreamBruto(
      chave,
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const contagens = [];
    for (let p = 0; p < this.tamanhoBloco; p++) {
      contagens[p] = new Array(256).fill(0);
    }

    for (let i = 0; i < this.amostrasDeBlocos; i++) {
      const ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        this.tamanhoBloco,
      );
      for (let p = 0; p < this.tamanhoBloco; p++) {
        contagens[p][ks[p]]++;
      }
    }

    const esperado = this.amostrasDeBlocos / 256;
    const problemas = [];
    let pior = 0.0;

    for (let p = 0; p < contagens.length; p++) {
      const c = contagens[p];
      let chi2 = 0.0;
      for (const v of c) {
        chi2 += ((v - esperado) ** 2) / esperado;
      }
      pior = Math.max(pior, chi2);
      const z = (chi2 - 255) / Math.sqrt(510);
      if (z > 4.0) {
        problemas.push(`posição ${p} chi2=${chi2.toFixed(1)}`);
      }
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'media', problemas.join('; '));
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${this.tamanhoBloco} posições uniformes (pior chi2=${pior.toFixed(1)}, esperado ~255)`,
    );
  }
}

module.exports = AtaqueDistribuicaoPorPosicao;

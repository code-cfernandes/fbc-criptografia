'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
 * previsibilidade local: para uma sequência aleatória, a chance de repetir um
 * bloco de m bits deve cair suavemente conforme m cresce. Estruturas
 * periódicas/recorrentes produzem ApEn anômala.
 *
 * O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
 * um valor esperado teórico. Comparamos o keystream com um CONTROLE de
 * random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
 * estatisticamente indistinguíveis.
 */
class AtaqueEntropiaAproximada {
  constructor({
    tamanho = 4096,
    m = 8,
    controles = 12,
    amostrasKeystream = 3,
    limiteZ = 5.0,
  } = {}) {
    this.tamanho = tamanho;
    this.m = m;
    this.controles = controles;
    this.amostrasKeystream = amostrasKeystream;
    this.limiteZ = limiteZ;
  }

  nome() {
    return 'Entropia aproximada (ApEn vs controle aleatório)';
  }

  executar(alvo) {
    const primeiro = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      64,
    );
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const chiControle = [];
    for (let c = 0; c < this.controles; c++) {
      chiControle.push(this.estatistico(randomBytes(this.tamanho)));
    }
    const mediaControle = chiControle.reduce((acc, v) => acc + v, 0) / chiControle.length;
    let variancia = 0.0;
    for (const v of chiControle) {
      variancia += (v - mediaControle) ** 2;
    }
    const desvioControle = Math.sqrt(variancia / Math.max(1, chiControle.length - 1));

    const chiKeystream = [];
    for (let k = 0; k < this.amostrasKeystream; k++) {
      const ks = alvo.gerarKeystreamBruto(
        alvo.chaveDeTeste(),
        randomBytes(alvo.tamanhoIv()),
        'enc',
        this.tamanho,
      );
      chiKeystream.push(this.estatistico(ks));
    }
    const mediaKeystream = chiKeystream.reduce((acc, v) => acc + v, 0) / chiKeystream.length;

    const z = desvioControle > 0 ? (mediaKeystream - mediaControle) / desvioControle : 0.0;
    const vulneravel = Math.abs(z) > this.limiteZ;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `chi2 keystream=${mediaKeystream.toFixed(1)}, controle=${mediaControle.toFixed(1)} (sd=${desvioControle.toFixed(1)}), z=${z.toFixed(2)} (limite=${this.limiteZ.toFixed(1)})`,
      { chi_keystream: mediaKeystream, chi_controle: mediaControle, z },
    );
  }

  /** chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1). */
  estatistico(bytes) {
    const bits = this.paraBits(bytes);
    const n = bits.length;
    const apen = this.phi(bits, this.m, n) - this.phi(bits, this.m + 1, n);
    return 2 * n * (Math.log(2) - apen);
  }

  phi(bits, m, n) {
    const total = 1 << m;
    const contagem = new Array(total).fill(0);
    const janelas = n - m + 1;

    for (let i = 0; i < janelas; i++) {
      let v = 0;
      for (let j = 0; j < m; j++) {
        v = (v << 1) | bits[i + j];
      }
      contagem[v]++;
    }

    let soma = 0.0;
    for (const c of contagem) {
      if (c > 0) {
        const p = c / janelas;
        soma += p * Math.log(p);
      }
    }

    return soma;
  }

  paraBits(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
      const byte = bytes[i];
      for (let b = 7; b >= 0; b--) {
        bits.push((byte >> b) & 1);
      }
    }
    return bits;
  }
}

module.exports = AtaqueEntropiaAproximada;

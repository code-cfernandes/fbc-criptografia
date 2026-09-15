'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomInt, randomBytes } = require('../Util.js');

/**
 * Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
 * IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
 * boa, essas diferenças são uniformes e únicas. Sinaliza:
 *  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
 *  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
 *    que é o insumo básico de um ataque diferencial.
 */
class AtaqueDiferencialKeystream {
  constructor({ amostras = 2000, tamanhoBloco = 32 } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome() {
    return 'Diferencial do keystream (delta fixo no IV)';
  }

  executar(alvo) {
    const chave = randomBytes(alvo.chaveDeTeste().length);
    const tamanhoIv = alvo.tamanhoIv();
    const primeiro = alvo.gerarKeystreamBruto(
      chave,
      randomBytes(tamanhoIv),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const delta = Buffer.alloc(tamanhoIv, 0);
    delta[randomInt(0, tamanhoIv - 1)] = 1 << randomInt(0, 7);

    const totalBits = this.tamanhoBloco * 8;
    const sempreZero = new Array(totalBits).fill(true);
    const sempreUm = new Array(totalBits).fill(true);
    const deltas = new Set();

    for (let i = 0; i < this.amostras; i++) {
      const iv = randomBytes(tamanhoIv);
      const iv2 = this.xorBytes(iv, delta);

      const ks1 = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);
      const ks2 = alvo.gerarKeystreamBruto(chave, iv2, 'enc', this.tamanhoBloco);
      const d = this.xorBytes(ks1, ks2);
      deltas.add(d.toString('hex'));

      for (let p = 0; p < d.length; p++) {
        const byte = d[p];
        for (let b = 0; b < 8; b++) {
          const idx = p * 8 + b;
          if (((byte >> b) & 1) === 1) {
            sempreZero[idx] = false;
          } else {
            sempreUm[idx] = false;
          }
        }
      }
    }

    let bitsFixos = 0;
    for (let idx = 0; idx < totalBits; idx++) {
      if (sempreZero[idx] || sempreUm[idx]) {
        bitsFixos++;
      }
    }
    const colisoes = this.amostras - deltas.size;

    const vulneravel = bitsFixos > 0 || colisoes > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `delta de 1 bit no IV: ${bitsFixos} bit(s) de saída fixo(s), ${colisoes} diferencial(is) repetido(s) em ${this.amostras} amostras`,
      { bits_fixos: bitsFixos, colisoes },
    );
  }

  xorBytes(a, b) {
    const out = Buffer.alloc(a.length);
    for (let i = 0; i < a.length; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

module.exports = AtaqueDiferencialKeystream;

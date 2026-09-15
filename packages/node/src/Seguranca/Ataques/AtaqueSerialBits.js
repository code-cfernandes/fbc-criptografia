'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
 * gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
 * locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
 * aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
 */
class AtaqueSerialBits {
  constructor({ tamanho = 4096, ordens = [2, 3, 4] } = {}) {
    this.tamanho = tamanho;
    this.ordens = ordens;
  }

  nome() {
    return 'Teste serial (padrões de bits sobrepostos)';
  }

  executar(alvo) {
    const ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanho,
    );
    if (ks == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const bits = this.paraBits(ks);
    const n = bits.length;

    const problemas = [];
    const dados = {};

    for (const m of this.ordens) {
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

      const esperado = janelas / total;
      let chi2 = 0.0;
      for (const c of contagem) {
        chi2 += ((c - esperado) ** 2) / esperado;
      }
      const dof = total - 1;
      const z = (chi2 - dof) / Math.sqrt(2 * dof);
      dados[`m${m}`] = { chi2, z };

      if (z > 4.0) {
        problemas.push(`m=${m} chi2=${chi2.toFixed(1)} (z=${z.toFixed(1)})`);
      }
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'media', problemas.join('; '), dados);
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      'Padrões sobrepostos de 2/3/4 bits com frequência uniforme',
      dados,
    );
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

module.exports = AtaqueSerialBits;

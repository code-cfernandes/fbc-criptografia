'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
 * (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
 * de cifra sólida deve parecer ruído mesmo com plaintext variado.
 */
class AtaqueCiphertextEstatistico {
  constructor({ amostras = 200, tamanhoTexto = 64, zLimite = 4 } = {}) {
    this.amostras = amostras;
    this.tamanhoTexto = tamanhoTexto;
    this.zLimite = zLimite;
  }

  nome() {
    return 'Estatística do ciphertext (chi²/runs/autocorrelação)';
  }

  executar(alvo) {
    const contagem = new Array(256).fill(0);
    const bytes = [];

    for (let s = 0; s < this.amostras; s++) {
      const texto = randomBytes(this.tamanhoTexto);
      const token = alvo.encrypt(texto);
      const campos = alvo.decompor(
        alvo.base64urlDecode(token.slice(alvo.prefixo().length)),
      );
      for (const b of campos.ciphertext) {
        contagem[b]++;
        bytes.push(b);
      }
    }

    const total = bytes.length;
    const esperado = total / 256;
    let chi2 = 0;
    for (let b = 0; b < 256; b++) {
      const d = contagem[b] - esperado;
      chi2 += (d * d) / esperado;
    }

    // runs test nos bits do ciphertext
    let uns = 0;
    const bits = [];
    for (const b of bytes) {
      for (let k = 7; k >= 0; k--) {
        const bit = (b >> k) & 1;
        bits.push(bit);
        uns += bit;
      }
    }
    const n = bits.length;
    const pi = uns / n;
    let runs = 1;
    for (let i = 1; i < n; i++) {
      if (bits[i] !== bits[i - 1]) runs++;
    }
    const esperadoRuns = 2 * n * pi * (1 - pi);
    const desvioRuns = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
    const zRuns = desvioRuns > 0 ? Math.abs(runs - esperadoRuns) / desvioRuns : 0;

    // autocorrelação lag-1
    const media = bytes.reduce((a, b) => a + b, 0) / total;
    let num = 0;
    let den = 0;
    for (let i = 0; i < total; i++) {
      den += (bytes[i] - media) ** 2;
    }
    for (let i = 0; i < total - 1; i++) {
      num += (bytes[i] - media) * (bytes[i + 1] - media);
    }
    const autocorr = den > 0 ? num / den : 0;

    const problemas = [];
    if (chi2 > 330) problemas.push(`qui-quadrado=${chi2.toFixed(1)} (>330 suspeito)`);
    if (zRuns > this.zLimite) problemas.push(`runs z=${zRuns.toFixed(2)}`);
    if (Math.abs(autocorr) > 0.1) problemas.push(`autocorrelação=${autocorr.toFixed(3)}`);

    const vulneravel = problemas.length > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      vulneravel
        ? problemas.join('; ')
        : `qui-quadrado=${chi2.toFixed(1)} sobre ${total} bytes, runs z=${zRuns.toFixed(2)}, ` +
            `autocorrelação=${autocorr.toFixed(3)} - todos dentro do esperado`,
      { chi2, runs_z: zRuns, autocorrelacao: autocorr },
    );
  }
}

module.exports = AtaqueCiphertextEstatistico;

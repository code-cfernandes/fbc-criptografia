'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
 * global (monobit), frequência por posição de bit, teste de runs e frequência
 * por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
 * e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
 *
 * Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
 * pra não depender de funções numéricas especiais.
 */
class AtaqueBateriaEstatistica {
  constructor({ tamanho = 16384, zLimite = 4.0 } = {}) {
    this.tamanho = tamanho;
    this.zLimite = zLimite;
  }

  nome() {
    return 'Bateria estatística de bits (monobit/runs/blocos)';
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

    const bits = this.paraBits(ks);
    const n = bits.length;
    const problemas = [];
    const dados = {};

    // 1) Monobit: soma +1/-1
    let soma = 0;
    for (const b of bits) {
      soma += b === 1 ? 1 : -1;
    }
    const zMonobit = Math.abs(soma) / Math.sqrt(n);
    dados.monobit_z = zMonobit;
    if (zMonobit > this.zLimite) {
      problemas.push(`monobit z=${zMonobit.toFixed(2)}`);
    }

    // 2) Frequência por posição de bit
    const unsPorPos = new Array(8).fill(0);
    const contaPorPos = new Array(8).fill(0);
    for (let i = 0; i < ks.length; i++) {
      const byte = ks[i];
      for (let b = 0; b < 8; b++) {
        if (((byte >> b) & 1) === 1) {
          unsPorPos[b]++;
        }
        contaPorPos[b]++;
      }
    }
    const posViesadas = {};
    for (let b = 0; b < 8; b++) {
      const frac = unsPorPos[b] / contaPorPos[b];
      const z = Math.abs(frac - 0.5) / (0.5 / Math.sqrt(contaPorPos[b]));
      if (z > this.zLimite) {
        posViesadas[b] = frac;
      }
    }
    dados.bit_posicao_viesadas = posViesadas;
    if (Object.keys(posViesadas).length > 0) {
      problemas.push('viés por posição de bit: ' + Object.keys(posViesadas).join(', '));
    }

    // 3) Runs test
    const pi = bits.reduce((acc, b) => acc + b, 0) / n;
    if (Math.abs(pi - 0.5) < 2 / Math.sqrt(n)) {
      let runs = 1;
      for (let i = 1; i < n; i++) {
        if (bits[i] !== bits[i - 1]) {
          runs++;
        }
      }
      const esperado = 2 * n * pi * (1 - pi);
      const desvio = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
      const zRuns = Math.abs(runs - esperado) / desvio;
      dados.runs_z = zRuns;
      if (zRuns > this.zLimite) {
        problemas.push(`runs z=${zRuns.toFixed(2)}`);
      }
    }

    // 4) Frequência por bloco (M = 128 bits)
    const m = 128;
    const numBlocos = Math.trunc(n / m);
    if (numBlocos > 0) {
      let chi = 0.0;
      for (let i = 0; i < numBlocos; i++) {
        let uns = 0;
        for (let j = 0; j < m; j++) {
          uns += bits[i * m + j];
        }
        chi += (uns / m - 0.5) ** 2;
      }
      chi *= 4 * m;
      const zBlocos = (chi - numBlocos) / Math.sqrt(2 * numBlocos);
      dados.blocos_chi2 = chi;
      dados.blocos_z = zBlocos;
      if (zBlocos > this.zLimite) {
        problemas.push(`frequência por bloco chi2=${chi.toFixed(1)}`);
      }
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'media', problemas.join('; '), dados);
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `monobit z=${zMonobit.toFixed(2)}, runs z=${(dados.runs_z ?? 0.0).toFixed(2)}, blocos chi2=${(dados.blocos_chi2 ?? 0.0).toFixed(1)} - todos abaixo do limite z=${this.zLimite.toFixed(0)}`,
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

module.exports = AtaqueBateriaEstatistica;

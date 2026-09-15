'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes, contarBitsBuffer } = require('../Util.js');

/**
 * O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
 * Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
 * autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
 * estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
 * keystream aleatório deve ter todos esses indicadores perto de zero/50%.
 */
class AtaqueAutocorrelacao {
  constructor({ tamanho = 8192, tamanhoBloco = 32 } = {}) {
    this.tamanho = tamanho;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome() {
    return 'Autocorrelação e periodicidade do keystream';
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

    const serial = this.correlacao(ks, 1);

    const suspeitos = {};
    for (const lag of [2, 4, 8, 16, 32, 64, 128, 256]) {
      const c = this.correlacao(ks, lag);
      if (Math.abs(c) > 0.1) {
        suspeitos[lag] = c;
      }
    }

    const blocos = [];
    for (let i = 0; i < ks.length; i += this.tamanhoBloco) {
      blocos.push(ks.subarray(i, i + this.tamanhoBloco));
    }
    const blocosUnicos = new Set(blocos.map((b) => b.toString('hex')));
    const blocosRepetidos = blocos.length - blocosUnicos.size;

    const uns = contarBitsBuffer(ks);
    const fracaoUns = uns / (ks.length * 8);

    const problemas = [];
    if (Math.abs(serial) > 0.1) {
      problemas.push(`correlação serial=${serial.toFixed(3)}`);
    }
    if (Object.keys(suspeitos).length > 0) {
      problemas.push('autocorrelação em lag(s) ' + Object.keys(suspeitos).join(', '));
    }
    if (blocosRepetidos > 0) {
      problemas.push(`${blocosRepetidos} bloco(s) de ${this.tamanhoBloco} bytes repetido(s)`);
    }
    if (fracaoUns < 0.45 || fracaoUns > 0.55) {
      problemas.push(`balanço de bits=${(fracaoUns * 100).toFixed(1)}% de 1s`);
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'media', problemas.join('; '));
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `serial=${serial.toFixed(3)}, nenhum lag com correlação >10%, 0 blocos repetidos em ${blocos.length}, ${(fracaoUns * 100).toFixed(1)}% de bits 1`,
    );
  }

  correlacao(s, lag) {
    const n = s.length;
    if (n <= lag) {
      return 0.0;
    }

    let soma = 0;
    for (let i = 0; i < n; i++) {
      soma += s[i];
    }
    const media = soma / n;

    let num = 0.0;
    let den = 0.0;
    for (let i = 0; i < n; i++) {
      den += (s[i] - media) ** 2;
    }
    for (let i = 0; i < n - lag; i++) {
      num += (s[i] - media) * (s[i + lag] - media);
    }

    return den > 0 ? num / den : 0.0;
  }
}

module.exports = AtaqueAutocorrelacao;

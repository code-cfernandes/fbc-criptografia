'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
 * primeira metade do keystream e mede a taxa de acerto na segunda metade.
 * Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
 * Qualquer coisa acima disso indica que os bits carregam dependência
 * explorável - o embrião de um ataque de predição de estado.
 */
class AtaquePreditorDeBits {
  constructor({ tamanho = 16384, contexto = 8, limiteTaxa = 0.55 } = {}) {
    this.tamanho = tamanho;
    this.contexto = contexto;
    this.limiteTaxa = limiteTaxa;
  }

  nome() {
    return 'Previsibilidade de bits (preditor por contexto)';
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
    const k = this.contexto;
    const total = 1 << k;
    const metade = Math.floor(n / 2);

    const uns = new Array(total).fill(0);
    const cont = new Array(total).fill(0);
    for (let i = k; i < metade; i++) {
      const ctx = this.contextoDe(bits, i, k);
      uns[ctx] += bits[i];
      cont[ctx]++;
    }

    let acertos = 0;
    let testes = 0;
    for (let i = metade; i < n; i++) {
      const ctx = this.contextoDe(bits, i, k);
      if (cont[ctx] === 0) {
        continue;
      }
      const predicao = uns[ctx] * 2 > cont[ctx] ? 1 : 0;
      if (predicao === bits[i]) {
        acertos++;
      }
      testes++;
    }

    const taxa = testes > 0 ? acertos / testes : 0.5;
    const vulneravel = taxa > this.limiteTaxa;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `taxa de acerto=${(taxa * 100).toFixed(2)}% com contexto de ${k} bits (esperado ~50%, limite=${(this.limiteTaxa * 100).toFixed(0)}%) sobre ${testes} testes`,
      { taxa, testes },
    );
  }

  contextoDe(bits, i, k) {
    let ctx = 0;
    for (let j = i - k; j < i; j++) {
      ctx = (ctx << 1) | bits[j];
    }
    return ctx;
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

module.exports = AtaquePreditorDeBits;

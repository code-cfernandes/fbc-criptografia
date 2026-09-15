'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
 * correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
 * posições de saída é exatamente o tipo de estrutura que o antigo bug da
 * "metade igual" produzia - e que a autocorrelação temporal pode não pegar.
 */
class AtaqueCorrelacaoPosicoes {
  constructor({ amostras = 3000, tamanhoBloco = 32, limiteCorrelacao = 0.15 } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
    this.limiteCorrelacao = limiteCorrelacao;
  }

  nome() {
    return 'Correlação entre posições do bloco';
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

    const blocos = [];
    for (let i = 0; i < this.amostras; i++) {
      blocos.push(
        alvo.gerarKeystreamBruto(chave, randomBytes(alvo.tamanhoIv()), 'enc', this.tamanhoBloco),
      );
    }

    const suspeitos = [];
    let pior = 0.0;

    for (let a = 0; a < this.tamanhoBloco; a++) {
      for (let b = a + 1; b < this.tamanhoBloco; b++) {
        const corr = this.pearson(blocos, a, b);
        if (Math.abs(corr) > Math.abs(pior)) {
          pior = corr;
        }
        if (Math.abs(corr) > this.limiteCorrelacao) {
          suspeitos.push(`posições ${a}-${b} (r=${corr.toFixed(3)})`);
        }
      }
    }

    if (suspeitos.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'alta',
        `${suspeitos.length} par(es) correlacionado(s): ${suspeitos.slice(0, 10).join('; ')}`,
        { suspeitos },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Nenhum par de posições correlacionado acima de ${this.limiteCorrelacao.toFixed(2)} (pior |r|=${Math.abs(pior).toFixed(3)})`,
    );
  }

  pearson(blocos, a, b) {
    const n = blocos.length;
    let ma = 0.0;
    let mb = 0.0;
    for (const d of blocos) {
      ma += d[a];
      mb += d[b];
    }
    ma /= n;
    mb /= n;

    let num = 0.0;
    let da = 0.0;
    let db = 0.0;
    for (const d of blocos) {
      const xa = d[a] - ma;
      const xb = d[b] - mb;
      num += xa * xb;
      da += xa * xa;
      db += xb * xb;
    }

    return da > 0 && db > 0 ? num / Math.sqrt(da * db) : 0.0;
  }
}

module.exports = AtaqueCorrelacaoPosicoes;

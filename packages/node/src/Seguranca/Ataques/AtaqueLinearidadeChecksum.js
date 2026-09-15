'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Procura linearidade no checksum, que seria fatal para um MAC:
 *  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
 *  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
 *     cada a; se repetir muito, existe um diferencial de alta probabilidade
 *     que ajuda a forjar MACs.
 */
class AtaqueLinearidadeChecksum {
  constructor({
    amostrasLinearidade = 5000,
    amostrasDiferencial = 500,
    tamanhoEntrada = 32,
  } = {}) {
    this.amostrasLinearidade = amostrasLinearidade;
    this.amostrasDiferencial = amostrasDiferencial;
    this.tamanhoEntrada = tamanhoEntrada;
  }

  nome() {
    return 'Linearidade e diferenciais do checksum';
  }

  executar(alvo) {
    const chaveMac = 'M'.repeat(32);
    const primeiro = alvo.checksumBruto('teste', chaveMac);
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
    }

    let relacoesLineares = 0;
    for (let i = 0; i < this.amostrasLinearidade; i++) {
      const a = randomBytes(this.tamanhoEntrada);
      const b = randomBytes(this.tamanhoEntrada);
      const lhs = this.xorBytes(
        alvo.checksumBruto(a, chaveMac),
        alvo.checksumBruto(b, chaveMac),
      );
      const rhs = alvo.checksumBruto(this.xorBytes(a, b), chaveMac);
      if (lhs.equals(rhs)) {
        relacoesLineares++;
      }
    }

    let maxRepeticoesDiferencial = 0;
    for (let d = 0; d < 5; d++) {
      const delta = randomBytes(this.tamanhoEntrada);
      const vistos = new Map();
      for (let i = 0; i < this.amostrasDiferencial; i++) {
        const a = randomBytes(this.tamanhoEntrada);
        const dif = this.xorBytes(
          alvo.checksumBruto(this.xorBytes(a, delta), chaveMac),
          alvo.checksumBruto(a, chaveMac),
        );
        const chaveDif = dif.toString('hex');
        vistos.set(chaveDif, (vistos.get(chaveDif) || 0) + 1);
      }
      let maxVistos = 0;
      for (const c of vistos.values()) {
        if (c > maxVistos) {
          maxVistos = c;
        }
      }
      maxRepeticoesDiferencial = Math.max(maxRepeticoesDiferencial, maxVistos);
    }

    const vulneravel = relacoesLineares > 0 || maxRepeticoesDiferencial > 1;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      `${relacoesLineares}/${this.amostrasLinearidade} relações lineares; maior repetição de diferencial=${maxRepeticoesDiferencial} (esperado 1)`,
      {
        relacoes_lineares: relacoesLineares,
        max_repeticoes_diferencial: maxRepeticoesDiferencial,
      },
    );
  }

  xorBytes(a, b) {
    const len = Math.min(a.length, b.length);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

module.exports = AtaqueLinearidadeChecksum;

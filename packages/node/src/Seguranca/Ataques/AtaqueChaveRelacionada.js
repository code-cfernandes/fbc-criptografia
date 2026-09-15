'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes, bitsDiferentes } = require('../Util.js');

/**
 * Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
 * 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
 * schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
 * estrutura (distância de Hamming baixa).
 */
class AtaqueChaveRelacionada {
  constructor({ tamanhoBloco = 32, ivPorDelta = 3, limiteMedia = 0.45, limitePior = 0.3 } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.ivPorDelta = ivPorDelta;
    this.limiteMedia = limiteMedia;
    this.limitePior = limitePior;
  }

  nome() {
    return 'Chave relacionada (related-key)';
  }

  executar(alvo) {
    const chaveBase = Buffer.from(alvo.chaveDeTeste(), 'utf8');
    const len = chaveBase.length;

    const deltas = [];
    for (let i = 0; i < len; i++) {
      const d = Buffer.alloc(len);
      d[i] = 0x01;
      deltas.push(d);
    }
    for (let i = 0; i < len; i++) {
      const d = Buffer.alloc(len);
      d[i] = 0xff;
      deltas.push(d);
    }
    const complemento = Buffer.from(chaveBase.map((b) => b ^ 0xff));
    deltas.push(complemento);

    const valores = [];
    const totalBits = this.tamanhoBloco * 8;

    for (const delta of deltas) {
      const chaveRelacionada = Buffer.from(chaveBase);
      for (let i = 0; i < len; i++) {
        chaveRelacionada[i] ^= delta[i];
      }
      for (let s = 0; s < this.ivPorDelta; s++) {
        const iv = randomBytes(alvo.tamanhoIv());
        const ks1 = alvo.gerarKeystreamBruto(chaveBase, iv, 'enc', this.tamanhoBloco);
        if (ks1 == null) {
          throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }
        const ks2 = alvo.gerarKeystreamBruto(chaveRelacionada, iv, 'enc', this.tamanhoBloco);
        valores.push(bitsDiferentes(ks1, ks2) / totalBits);
      }
    }

    const media = valores.reduce((a, b) => a + b, 0) / valores.length;
    const pior = Math.min(...valores);
    const vulneravel = media < this.limiteMedia || pior < this.limitePior;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `média=${(media * 100).toFixed(1)}%, pior=${(pior * 100).toFixed(1)}% ` +
        `em ${valores.length} pares (limites: média>=${(this.limiteMedia * 100).toFixed(0)}%, ` +
        `pior>=${(this.limitePior * 100).toFixed(0)}%)`,
      { media, pior },
    );
  }
}

module.exports = AtaqueChaveRelacionada;

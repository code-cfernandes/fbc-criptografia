'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { contarBitsBuffer } = require('../Util.js');

/**
 * Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
 * produzir keystream anômalo (repetição, período curto, viés de bits ou
 * distribuição de bytes distorcida). Complementa o ataque de chaves
 * degeneradas, que só checa a saída do encrypt.
 */
class AtaqueChavesFracas {
  constructor({ tamanho = 2048, toleranciaBits = 0.05 } = {}) {
    this.tamanho = tamanho;
    this.toleranciaBits = toleranciaBits;
  }

  nome() {
    return 'Chaves fracas (busca dirigida)';
  }

  executar(alvo) {
    const len = Buffer.byteLength(alvo.chaveDeTeste(), 'utf8');
    const casos = [
      { nome: 'zeros', chave: Buffer.alloc(len, 0x00) },
      { nome: '0xFF', chave: Buffer.alloc(len, 0xff) },
      {
        nome: 'alternada AA/55',
        chave: Buffer.from(Array.from({ length: len }, (_, i) => (i % 2 === 0 ? 0xaa : 0x55))),
      },
      { nome: 'incremental', chave: Buffer.from(Array.from({ length: len }, (_, i) => i & 0xff)) },
      {
        nome: 'um bit',
        chave: Buffer.from(Array.from({ length: len }, (_, i) => (i === 0 ? 1 : 0))),
      },
      { nome: 'byte repetido 0x01', chave: Buffer.alloc(len, 0x01) },
      {
        nome: 'padrão AB',
        chave: Buffer.from(Array.from({ length: len }, (_, i) => (i % 2 === 0 ? 0x41 : 0x42))),
      },
    ];

    const ivFixo = Buffer.alloc(alvo.tamanhoIv());
    const anomalias = [];

    for (const caso of casos) {
      const ks = alvo.gerarKeystreamBruto(caso.chave, ivFixo, 'enc', this.tamanho);
      if (ks == null) {
        throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
      }

      const blocos = new Set();
      let repetidos = 0;
      for (let i = 0; i + 32 <= ks.length; i += 32) {
        const hex = ks.subarray(i, i + 32).toString('hex');
        if (blocos.has(hex)) repetidos++;
        else blocos.add(hex);
      }

      const fracaoUns = contarBitsBuffer(ks) / (ks.length * 8);
      const desvioBits = Math.abs(fracaoUns - 0.5);

      if (repetidos > 0) anomalias.push(`${caso.nome}: ${repetidos} bloco(s) repetido(s)`);
      if (desvioBits > this.toleranciaBits) {
        anomalias.push(`${caso.nome}: viés de bits ${(fracaoUns * 100).toFixed(1)}%`);
      }
    }

    const vulneravel = anomalias.length > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      vulneravel
        ? `Anomalias: ${anomalias.slice(0, 5).join('; ')}`
        : `Nenhuma das ${casos.length} chaves fracas produziu keystream anômalo (${this.tamanho} bytes cada)`,
      { anomalias },
    );
  }
}

module.exports = AtaqueChavesFracas;

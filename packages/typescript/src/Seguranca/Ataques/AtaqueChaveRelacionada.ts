import { randomBytes, bitsDiferentes } from '../Util.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';

/**
 * Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
 * 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
 * schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
 * estrutura (distância de Hamming baixa).
 */
export class AtaqueChaveRelacionada implements AtaqueInterface {
  private readonly tamanhoBloco: number;
  private readonly ivPorDelta: number;
  private readonly limiteMedia: number;
  private readonly limitePior: number;

  constructor({
    tamanhoBloco = 32,
    ivPorDelta = 3,
    limiteMedia = 0.45,
    limitePior = 0.3,
  }: {
    tamanhoBloco?: number;
    ivPorDelta?: number;
    limiteMedia?: number;
    limitePior?: number;
  } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.ivPorDelta = ivPorDelta;
    this.limiteMedia = limiteMedia;
    this.limitePior = limitePior;
  }

  nome(): string {
    return 'Chave relacionada (related-key)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chaveBase = Buffer.from(alvo.chaveDeTeste(), 'utf8');
    const len = chaveBase.length;

    const deltas: Buffer[] = [];
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

    const valores: number[] = [];
    const totalBits = this.tamanhoBloco * 8;

    for (const delta of deltas) {
      const chaveRelacionada = Buffer.from(chaveBase);
      for (let i = 0; i < len; i++) {
        chaveRelacionada[i] ^= delta[i];
      }
      for (let s = 0; s < this.ivPorDelta; s++) {
        const iv = randomBytes(alvo.tamanhoIv());
        const ks1 = alvo.gerarKeystreamBruto(chaveBase, iv, 'enc', this.tamanhoBloco);
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

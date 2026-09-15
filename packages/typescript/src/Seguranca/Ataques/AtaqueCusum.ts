import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

interface OpcoesCusum {
  tamanho?: number;
  limiteZ?: number;
}

/**
 * Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
 * passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
 * pequeno que o monobit quase não vê faz o desvio acumulado crescer.
 * Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
 */
export class AtaqueCusum implements AtaqueInterface {
  private readonly tamanho: number;
  private readonly limiteZ: number;

  constructor({ tamanho = 8192, limiteZ = 4.0 }: OpcoesCusum = {}) {
    this.tamanho = tamanho;
    this.limiteZ = limiteZ;
  }

  nome(): string {
    return 'Somas cumulativas (cusum)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const ks = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanho,
    );
    if (ks === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    let soma = 0;
    let maxAbs = 0;
    for (let i = 0; i < ks.length; i++) {
      const byte = ks[i];
      for (let b = 7; b >= 0; b--) {
        soma += ((byte >> b) & 1) === 1 ? 1 : -1;
        maxAbs = Math.max(maxAbs, Math.abs(soma));
      }
    }
    const n = ks.length * 8;
    const z = maxAbs / Math.sqrt(n);
    const vulneravel = z > this.limiteZ;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `max|S|=${maxAbs} sobre ${n} bits, max|S|/sqrt(n)=${z.toFixed(2)} (limite=${this.limiteZ.toFixed(1)})`,
      { max_abs: maxAbs, z },
    );
  }
}

import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';

/**
 * Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
 * reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
 * complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
 * um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
 * seria atacável resolvendo um sistema linear em vez de força bruta.
 */
export class AtaqueComplexidadeLinear implements AtaqueInterface {
  private readonly bitsPorAmostra: number;
  private readonly amostras: number;
  private readonly limiteRelativo: number;

  constructor({ bitsPorAmostra = 1024, amostras = 5, limiteRelativo = 0.4 }: { bitsPorAmostra?: number; amostras?: number; limiteRelativo?: number } = {}) {
    this.bitsPorAmostra = bitsPorAmostra;
    this.amostras = amostras;
    this.limiteRelativo = limiteRelativo;
  }

  nome(): string {
    return 'Complexidade linear (Berlekamp-Massey)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = alvo.chaveDeTeste();
    const primeiro: Buffer | null = alvo.gerarKeystreamBruto(chave, randomBytes(alvo.tamanhoIv()), 'enc', 64);
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const relativos: number[] = [];
    let pior = 1.0;
    for (let a = 0; a < this.amostras; a++) {
      const bytes = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        Math.floor(this.bitsPorAmostra / 8),
      );
      const bits = this.paraBits(bytes, this.bitsPorAmostra);
      const relativo = this.berlekampMassey(bits) / this.bitsPorAmostra;
      relativos.push(relativo);
      pior = Math.min(pior, relativo);
    }

    const media = relativos.reduce((s, v) => s + v, 0) / relativos.length;
    const vulneravel = pior < this.limiteRelativo;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      `complexidade linear relativa: média=${(media * 100).toFixed(1)}%, pior=${(pior * 100).toFixed(1)}% de ${this.bitsPorAmostra} bits (esperado ~50%; limite>=${(this.limiteRelativo * 100).toFixed(0)}%)`,
      { media, pior },
    );
  }

  paraBits(bytes: Buffer, limite: number): number[] {
    const bits: number[] = [];
    for (let i = 0; i < bytes.length && bits.length < limite; i++) {
      const byte = bytes[i];
      for (let b = 7; b >= 0; b--) {
        bits.push((byte >> b) & 1);
      }
    }
    return bits.slice(0, limite);
  }

  /** Algoritmo de Berlekamp-Massey sobre GF(2). */
  berlekampMassey(s: number[]): number {
    const n = s.length;
    const c = new Array<number>(n).fill(0);
    c[0] = 1;
    const b = new Array<number>(n).fill(0);
    b[0] = 1;
    let l = 0;
    let m = -1;

    for (let i = 0; i < n; i++) {
      let d = s[i];
      for (let j = 1; j <= l; j++) {
        d ^= c[j] & s[i - j];
      }

      if (d === 1) {
        const t = c.slice();
        const shift = i - m;
        for (let j = 0; j + shift < n; j++) {
          c[j + shift] ^= b[j];
        }
        if (l <= Math.floor(i / 2)) {
          l = i + 1 - l;
          m = i;
          b.splice(0, n, ...t);
        }
      }
    }

    return l;
  }
}

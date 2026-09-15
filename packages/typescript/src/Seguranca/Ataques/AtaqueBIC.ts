import { randomBytes, randomInt } from '../Util.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';

/**
 * BIC (Bit Independence Criterion): pares de bits de saída não devem estar
 * correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
 * e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
 * cada par de bits de saída. Pares muito correlacionados indicam difusão
 * acoplada (um bit "carrega" informação sobre outro).
 */
export class AtaqueBIC implements AtaqueInterface {
  private readonly tamanhoBloco: number;
  private readonly amostras: number;
  private readonly limite: number;

  constructor({
    tamanhoBloco = 32,
    amostras = 300,
    limite = 0.35,
  }: { tamanhoBloco?: number; amostras?: number; limite?: number } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.amostras = amostras;
    this.limite = limite;
  }

  nome(): string {
    return 'BIC (Bit Independence Criterion)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = Buffer.from(alvo.chaveDeTeste(), 'utf8');
    const totalBits = this.tamanhoBloco * 8;
    const tamanhoIv = alvo.tamanhoIv();

    const amostrasFlips: Uint8Array[] = [];
    for (let s = 0; s < this.amostras; s++) {
      const iv1 = randomBytes(tamanhoIv);
      const iv2 = Buffer.from(iv1);
      const pos = randomInt(0, tamanhoIv - 1);
      iv2[pos] ^= 1 << randomInt(0, 7);

      const ks1 = alvo.gerarKeystreamBruto(chave, iv1, 'enc', this.tamanhoBloco);
      const ks2 = alvo.gerarKeystreamBruto(chave, iv2, 'enc', this.tamanhoBloco);

      const flips = new Uint8Array(totalBits);
      for (let j = 0; j < totalBits; j++) {
        const b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1;
        const b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1;
        flips[j] = b1 !== b2 ? 1 : 0;
      }
      amostrasFlips.push(flips);
    }

    let piorPhi = 0;
    let piorPar: [number, number] = [-1, -1];
    const n = this.amostras;

    for (let a = 0; a < totalBits; a++) {
      for (let b = a + 1; b < totalBits; b++) {
        let n11 = 0;
        let n10 = 0;
        let n01 = 0;
        let n00 = 0;
        for (let s = 0; s < n; s++) {
          const fa = amostrasFlips[s][a];
          const fb = amostrasFlips[s][b];
          if (fa === 1 && fb === 1) n11++;
          else if (fa === 1 && fb === 0) n10++;
          else if (fa === 0 && fb === 1) n01++;
          else n00++;
        }
        const den = Math.sqrt(
          (n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00),
        );
        const phi = den > 0 ? (n11 * n00 - n10 * n01) / den : 0;
        if (Math.abs(phi) > Math.abs(piorPhi)) {
          piorPhi = phi;
          piorPar = [a, b];
        }
      }
    }

    const vulneravel = Math.abs(piorPhi) > this.limite;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `maior |phi|=${Math.abs(piorPhi).toFixed(3)} entre bits de saída ` +
        `[${piorPar[0]}, ${piorPar[1]}] (limite ${this.limite}); ${n} amostras`,
      { pior_phi: piorPhi, par: piorPar },
    );
  }
}

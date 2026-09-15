import { randomBytes } from '../Util.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';

/**
 * Aproximação linear (criptoanálise de Matsui): procura por correlação entre
 * bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
 * aproximação linear com viés relevante; bias alto é uma pista explorável.
 */
export class AtaqueAproximacaoLinear implements AtaqueInterface {
  private readonly amostras: number;
  private readonly tamanhoBloco: number;
  private readonly limiteBias: number;

  constructor({
    amostras = 200,
    tamanhoBloco = 32,
    limiteBias = 0.3,
  }: { amostras?: number; tamanhoBloco?: number; limiteBias?: number } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
    this.limiteBias = limiteBias;
  }

  nome(): string {
    return 'Aproximação linear (viés de Walsh)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const tamIv = alvo.tamanhoIv();
    const bitsEntrada = tamIv * 8;
    const bitsSaida = this.tamanhoBloco * 8;

    const entradas: Uint8Array[] = [];
    const saidas: Uint8Array[] = [];

    for (let s = 0; s < this.amostras; s++) {
      const chave = randomBytes(Buffer.byteLength(alvo.chaveDeTeste(), 'utf8'));
      const iv = randomBytes(tamIv);
      const ks = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);

      const inBits = new Uint8Array(bitsEntrada);
      for (let j = 0; j < bitsEntrada; j++) {
        inBits[j] = (iv[j >> 3] >> (7 - (j & 7))) & 1;
      }
      const outBits = new Uint8Array(bitsSaida);
      for (let j = 0; j < bitsSaida; j++) {
        outBits[j] = (ks[j >> 3] >> (7 - (j & 7))) & 1;
      }
      entradas.push(inBits);
      saidas.push(outBits);
    }

    let maiorBias = 0;
    let par: [number, number] = [-1, -1];
    for (let i = 0; i < bitsEntrada; i++) {
      for (let j = 0; j < bitsSaida; j++) {
        let iguais = 0;
        for (let s = 0; s < this.amostras; s++) {
          if (entradas[s][i] === saidas[s][j]) iguais++;
        }
        const bias = Math.abs(iguais / this.amostras - 0.5);
        if (bias > maiorBias) {
          maiorBias = bias;
          par = [i, j];
        }
      }
    }

    const vulneravel = maiorBias > this.limiteBias;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `maior viés |p-0.5|=${maiorBias.toFixed(4)} na aproximação ` +
        `IV[bit ${par[0]}] -> saída[bit ${par[1]}] (limite ${this.limiteBias}); ` +
        `${this.amostras} amostras`,
      { maior_bias: maiorBias, par },
    );
  }
}

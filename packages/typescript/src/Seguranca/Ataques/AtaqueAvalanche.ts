import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomInt, randomBytes, bitsDiferentes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
 * gerado (efeito avalanche). Números muito abaixo disso indicam difusão
 * fraca - foi o que achamos quando o número de rodadas de mistura era
 * baixo demais numa das versões anteriores.
 */
export class AtaqueAvalanche implements AtaqueInterface {
  private readonly amostras: number;
  private readonly tamanhoBloco: number;
  private readonly limiteMedia: number;
  private readonly limitePiorCaso: number;

  constructor({
    amostras = 3000,
    tamanhoBloco = 32,
    limiteMedia = 0.45,
    limitePiorCaso = 0.3,
  }: {
    amostras?: number;
    tamanhoBloco?: number;
    limiteMedia?: number;
    limitePiorCaso?: number;
  } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
    this.limiteMedia = limiteMedia;
    this.limitePiorCaso = limitePiorCaso;
  }

  nome(): string {
    return 'Efeito avalanche';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = alvo.chaveDeTeste();
    const tamanhoIv = alvo.tamanhoIv();

    const primeiro = alvo.gerarKeystreamBruto(chave, randomBytes(tamanhoIv), 'enc', this.tamanhoBloco);
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const valores: number[] = [];
    for (let t = 0; t < this.amostras; t++) {
      const iv1 = randomBytes(tamanhoIv);
      const iv2 = Buffer.from(iv1);
      const pos = randomInt(0, tamanhoIv - 1);
      iv2[pos] = iv2[pos] ^ (1 << randomInt(0, 7));

      const ks1 = alvo.gerarKeystreamBruto(chave, iv1, 'enc', this.tamanhoBloco);
      const ks2 = alvo.gerarKeystreamBruto(chave, iv2, 'enc', this.tamanhoBloco);

      valores.push(bitsDiferentes(ks1, ks2) / (this.tamanhoBloco * 8));
    }

    valores.sort((a, b) => a - b);
    const n = valores.length;
    const media = valores.reduce((acc, v) => acc + v, 0) / n;
    const piorCaso = valores[0];

    const vulneravel = media < this.limiteMedia || piorCaso < this.limitePiorCaso;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `média=${(media * 100).toFixed(1)}%, pior caso=${(piorCaso * 100).toFixed(1)}%, percentil 1%=${(valores[Math.trunc(n * 0.01)] * 100).toFixed(1)}% (limites: média>=${(this.limiteMedia * 100).toFixed(0)}%, pior>=${(this.limitePiorCaso * 100).toFixed(0)}%)`,
      { media: media, pior_caso: piorCaso },
    );
  }
}

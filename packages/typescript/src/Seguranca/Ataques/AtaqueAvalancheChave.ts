import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomInt, randomBytes, bitsDiferentes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
 * CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
 * inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
 * Números baixos indicam que parte da chave tem pouca influência - o que
 * reduziria o espaço de busca de um atacante.
 */
export class AtaqueAvalancheChave implements AtaqueInterface {
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
    return 'Efeito avalanche da chave';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chaveBase = Buffer.from(alvo.chaveDeTeste(), 'binary');
    const lenChave = chaveBase.length;
    const iv = randomBytes(alvo.tamanhoIv());

    const primeiro = alvo.gerarKeystreamBruto(chaveBase, iv, 'enc', this.tamanhoBloco);
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const valores: number[] = [];
    for (let t = 0; t < this.amostras; t++) {
      const chave = Buffer.from(chaveBase);
      const pos = randomInt(0, lenChave - 1);
      chave[pos] = chave[pos] ^ (1 << randomInt(0, 7));

      const ks1 = alvo.gerarKeystreamBruto(chaveBase, iv, 'enc', this.tamanhoBloco);
      const ks2 = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);

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
      `média=${(media * 100).toFixed(1)}%, pior caso=${(piorCaso * 100).toFixed(1)}% (limites: média>=${(this.limiteMedia * 100).toFixed(0)}%, pior>=${(this.limitePiorCaso * 100).toFixed(0)}%)`,
      { media: media, pior_caso: piorCaso },
    );
  }
}

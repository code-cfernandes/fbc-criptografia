import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

interface OpcoesDistribuicaoPorPosicao {
  amostrasDeBlocos?: number;
  tamanhoBloco?: number;
}

/**
 * O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
 * bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
 * soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
 */
export class AtaqueDistribuicaoPorPosicao implements AtaqueInterface {
  private readonly amostrasDeBlocos: number;
  private readonly tamanhoBloco: number;

  constructor({
    amostrasDeBlocos = 2000,
    tamanhoBloco = 32,
  }: OpcoesDistribuicaoPorPosicao = {}) {
    this.amostrasDeBlocos = amostrasDeBlocos;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome(): string {
    return 'Distribuição de bytes por posição do bloco';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = alvo.chaveDeTeste();
    const primeiro = alvo.gerarKeystreamBruto(
      chave,
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const contagens: number[][] = [];
    for (let p = 0; p < this.tamanhoBloco; p++) {
      contagens[p] = new Array(256).fill(0);
    }

    for (let i = 0; i < this.amostrasDeBlocos; i++) {
      const ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        this.tamanhoBloco,
      );
      for (let p = 0; p < this.tamanhoBloco; p++) {
        contagens[p][ks[p]]++;
      }
    }

    const esperado = this.amostrasDeBlocos / 256;
    const problemas: string[] = [];
    let pior = 0.0;

    for (let p = 0; p < contagens.length; p++) {
      const c = contagens[p];
      let chi2 = 0.0;
      for (const v of c) {
        chi2 += ((v - esperado) ** 2) / esperado;
      }
      pior = Math.max(pior, chi2);
      const z = (chi2 - 255) / Math.sqrt(510);
      if (z > 4.0) {
        problemas.push(`posição ${p} chi2=${chi2.toFixed(1)}`);
      }
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'media', problemas.join('; '));
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${this.tamanhoBloco} posições uniformes (pior chi2=${pior.toFixed(1)}, esperado ~255)`,
    );
  }
}

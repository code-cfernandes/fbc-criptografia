import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

interface OpcoesDistribuicaoBytes {
  amostrasDeBlocos?: number;
  tamanhoBloco?: number;
}

/**
 * Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
 * 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
 * de byte saem com mais frequência que outros - sinal de fraqueza estatística
 * na função de mistura.
 */
export class AtaqueDistribuicaoBytes implements AtaqueInterface {
  private readonly amostrasDeBlocos: number;
  private readonly tamanhoBloco: number;

  constructor({ amostrasDeBlocos = 500, tamanhoBloco = 32 }: OpcoesDistribuicaoBytes = {}) {
    this.amostrasDeBlocos = amostrasDeBlocos;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome(): string {
    return 'Distribuição de bytes (qui-quadrado)';
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

    const contagem: number[] = new Array(256).fill(0);
    let total = 0;
    for (let i = 0; i < this.amostrasDeBlocos; i++) {
      const ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        this.tamanhoBloco,
      );
      for (let j = 0; j < ks.length; j++) {
        contagem[ks[j]]++;
        total++;
      }
    }

    const esperado = total / 256;
    let qui2 = 0.0;
    for (const c of contagem) {
      qui2 += ((c - esperado) ** 2) / esperado;
    }

    // Com 255 graus de liberdade, valores acima de ~330 já são
    // estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
    const vulneravel = qui2 > 330;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `qui-quadrado=${qui2.toFixed(1)} sobre ${total} bytes (255 graus de liberdade; >330 é suspeito)`,
      { qui2 },
    );
  }
}

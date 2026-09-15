import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes, bitsDiferentes } from '../Util.ts';
import type { Severidade } from '../ResultadoAtaque.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
 * interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
 * dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
 * posição específica significa que aquele byte quase não influencia o MAC -
 * uma pista forte de que a mistura tem um "ponto cego" estrutural.
 *
 * Varre TODAS as posições/bits da entrada (não amostra aleatória) para
 * apontar exatamente onde está o ponto fraco.
 */
export class AtaqueAvalancheChecksum implements AtaqueInterface {
  private readonly mensagensPorCombinacao: number;
  private readonly tamanhoEntrada: number;
  private readonly limiteMedia: number;
  private readonly limitePiorCaso: number;

  constructor({
    mensagensPorCombinacao = 10,
    tamanhoEntrada = 32,
    limiteMedia = 0.4,
    limitePiorCaso = 0.4,
  }: {
    mensagensPorCombinacao?: number;
    tamanhoEntrada?: number;
    limiteMedia?: number;
    limitePiorCaso?: number;
  } = {}) {
    this.mensagensPorCombinacao = mensagensPorCombinacao;
    this.tamanhoEntrada = tamanhoEntrada;
    this.limiteMedia = limiteMedia;
    this.limitePiorCaso = limitePiorCaso;
  }

  nome(): string {
    return 'Efeito avalanche do checksum/MAC';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chaveMac = 'M'.repeat(32);

    const primeiro = alvo.checksumBruto('teste', chaveMac);
    if (primeiro === null) {
      throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
    }
    const tamanhoSaida = primeiro.length;

    let somaGlobal = 0.0;
    let combinacoes = 0;
    let pior = { posicao: -1, bit: -1, valor: 1.0 };

    for (let pos = 0; pos < this.tamanhoEntrada; pos++) {
      for (let bit = 0; bit < 8; bit++) {
        let soma = 0.0;
        for (let m = 0; m < this.mensagensPorCombinacao; m++) {
          const entrada = randomBytes(this.tamanhoEntrada);
          const alterada = Buffer.from(entrada);
          alterada[pos] = alterada[pos] ^ (1 << bit);

          const h1 = alvo.checksumBruto(entrada, chaveMac);
          const h2 = alvo.checksumBruto(alterada, chaveMac);

          soma += bitsDiferentes(h1, h2) / (tamanhoSaida * 8);
        }
        const media = soma / this.mensagensPorCombinacao;

        somaGlobal += media;
        combinacoes++;
        if (media < pior.valor) {
          pior = { posicao: pos, bit: bit, valor: media };
        }
      }
    }

    const mediaGlobal = somaGlobal / combinacoes;
    const vulneravel = mediaGlobal < this.limiteMedia || pior.valor < this.limitePiorCaso;

    let severidade: Severidade;
    if (!vulneravel) {
      severidade = 'info';
    } else if (pior.valor < 0.3) {
      severidade = 'alta';
    } else {
      severidade = 'media';
    }

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      severidade,
      `média global=${(mediaGlobal * 100).toFixed(1)}%; pior caso=${(pior.valor * 100).toFixed(1)}% na entrada[posição=${pior.posicao}, bit=${pior.bit}] sobre ${tamanhoSaida} bytes de MAC (limites: média>=${(this.limiteMedia * 100).toFixed(0)}%, pior>=${(this.limitePiorCaso * 100).toFixed(0)}%)`,
      { media_global: mediaGlobal, pior: pior },
    );
  }
}

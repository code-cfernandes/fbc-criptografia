import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';

/**
 * Procura colisões no checksum() via paradoxo do aniversário: gera muitas
 * mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
 * propósito aqui - testar resistência a colisão é uma propriedade do
 * ALGORITMO, independente de a chave ser secreta ou não; é assim que se
 * testa qualquer função de hash/MAC na prática).
 *
 * Testa dois níveis:
 * 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
 *    aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
 *    tentativas pelo paradoxo do aniversário).
 * 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
 *    estatisticamente com poucas dezenas de milhares de tentativas (o
 *    paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
 *    pra 50% de chance). Isso não quebra o MAC completo (que depende dos
 *    32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
 *    útil pra saber se a composição das rodadas está de fato preservando
 *    a força total, ou se há alguma correlação entre elas.
 */
export class AtaqueColisaoChecksum implements AtaqueInterface {
  private readonly amostras: number;

  constructor({ amostras = 200000 }: { amostras?: number } = {}) {
    this.amostras = amostras;
  }

  nome(): string {
    return 'Colisão no checksum (paradoxo do aniversário)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chaveDeMac = 'M'.repeat(32); // chave conhecida de propósito - ver docblock

    const primeiro: Buffer | null = alvo.checksumBruto('teste', chaveDeMac);
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe checksumBruto.');
    }

    const vistosCompleto = new Map<string, Buffer>();
    const vistosTruncado = new Map<string, Buffer>();
    let colisaoCompleta: [Buffer, Buffer] | null = null;
    let colisaoTruncada: [Buffer, Buffer] | null = null;

    for (let i = 0; i < this.amostras; i++) {
      const mensagem = randomBytes(20);
      const hash = alvo.checksumBruto(mensagem, chaveDeMac);

      if (colisaoCompleta === null) {
        const chaveHash = hash.toString('hex');
        const anterior = vistosCompleto.get(chaveHash);
        if (anterior !== undefined) {
          colisaoCompleta = [anterior, mensagem];
        } else {
          vistosCompleto.set(chaveHash, mensagem);
        }
      }

      if (colisaoTruncada === null) {
        const truncado = hash.subarray(0, 4).toString('hex');
        const anterior = vistosTruncado.get(truncado);
        if (anterior !== undefined) {
          colisaoTruncada = [anterior, mensagem];
        } else {
          vistosTruncado.set(truncado, mensagem);
        }
      }

      if (colisaoCompleta !== null && colisaoTruncada !== null) {
        break;
      }
    }

    // Colisão no checksum COMPLETO com essa amostra pequena seria uma
    // falha estrutural séria (a probabilidade por acaso é desprezível).
    if (colisaoCompleta !== null) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `COLISÃO COMPLETA encontrada em ${vistosCompleto.size} amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.`,
        { msg1_hex: colisaoCompleta[0].toString('hex'), msg2_hex: colisaoCompleta[1].toString('hex') },
      );
    }

    // Colisão truncada (32 bits) é esperada estatisticamente - não é
    // "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
    // força que deveriam ter (nem mais, nem menos).
    const infoTruncada =
      colisaoTruncada !== null
        ? `colisão de 32 bits encontrada em ${vistosTruncado.size} amostras (esperado pelo paradoxo do aniversário)`
        : `nenhuma colisão de 32 bits em ${vistosTruncado.size} amostras (um pouco abaixo do esperado, mas não conclusivo)`;

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Nenhuma colisão completa em ${this.amostras} amostras (esperado). Nível truncado (32 bits): ${infoTruncada}.`,
      { amostras_completo: vistosCompleto.size, amostras_truncado: vistosTruncado.size },
    );
  }
}

import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { CriptografiaAlvo } from '../CriptografiaAlvo.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';

interface OpcoesValidacaoChave {
  tamanhos?: number[];
}

/**
 * A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
 * rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
 * bytes válida deve funcionar. Uma validação frouxa aqui vira uma chave mais
 * curta (e mais fraca) na prática.
 */
export class AtaqueValidacaoChave implements AtaqueInterface {
  private readonly tamanhos: number[];

  constructor({ tamanhos = [0, 1, 16, 31, 33, 64] }: OpcoesValidacaoChave = {}) {
    this.tamanhos = tamanhos;
  }

  nome(): string {
    return 'Validação do tamanho da chave';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de CriptografiaAlvo para trocar a chave.');
    }

    const chaveOriginal = alvo.chaveDeTeste();
    const aceitasIndevidamente: number[] = [];
    let validaRejeitada = false;

    try {
      for (const len of this.tamanhos) {
        new CriptografiaAlvo('K'.repeat(len));
        try {
          alvo.encrypt('x');
          aceitasIndevidamente.push(len);
        } catch (e) {
          // esperado
        }
      }

      new CriptografiaAlvo('K'.repeat(32));
      try {
        alvo.encrypt('x');
      } catch (e) {
        validaRejeitada = true;
      }
    } finally {
      process.env.FBC_KEY = chaveOriginal;
    }

    const vulneravel = aceitasIndevidamente.length > 0 || validaRejeitada;

    const detalhes: string[] = [];
    if (aceitasIndevidamente.length > 0) {
      detalhes.push('chaves de tamanho inválido aceitas: ' + aceitasIndevidamente.join(', '));
    }
    if (validaRejeitada) {
      detalhes.push('chave válida de 32 bytes foi rejeitada');
    }

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      vulneravel
        ? detalhes.join('; ')
        : 'Tamanhos inválidos rejeitados e chave de 32 bytes aceita',
    );
  }
}

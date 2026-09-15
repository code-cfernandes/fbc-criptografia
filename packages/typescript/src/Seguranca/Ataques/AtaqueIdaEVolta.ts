import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
 * de decrypt precisa devolver o texto original, em qualquer tamanho.
 * Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
 * segurança mais sério por trás (foi assim em quase todas as rodadas
 * anteriores dessa conversa).
 */
export class AtaqueIdaEVolta implements AtaqueInterface {
  private readonly tamanhoMaximo: number;

  constructor({ tamanhoMaximo = 130 }: { tamanhoMaximo?: number } = {}) {
    this.tamanhoMaximo = tamanhoMaximo;
  }

  nome(): string {
    return 'Ida-e-volta (round trip)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const falhas: (number | string)[] = [];
    for (let len = 0; len <= this.tamanhoMaximo; len++) {
      const texto = 'Q'.repeat(len);
      try {
        const token = alvo.encrypt(texto);
        const decifrado = alvo.decrypt(token);
        if (decifrado !== texto) {
          falhas.push(len);
        }
      } catch (e) {
        const mensagem = e instanceof Error ? e.message : String(e);
        falhas.push(`${len} (erro: ${mensagem})`);
      }
    }

    if (falhas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        'Falhou em ' + falhas.length + ' tamanho(s): ' + falhas.slice(0, 10).join(', '),
        { falhas },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todos os ${this.tamanhoMaximo + 1} tamanhos (0 a ${this.tamanhoMaximo}) OK`,
    );
  }
}

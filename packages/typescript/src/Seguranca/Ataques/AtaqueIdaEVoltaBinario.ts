import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { randomBytes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
 * verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
 * vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
 * truncation) só aparecem com bytes arbitrários.
 *
 * Adaptação Node: os dados são Buffers; como decrypt() devolve string
 * (UTF-8), comparamos com a representação UTF-8 dos mesmos bytes.
 */
export class AtaqueIdaEVoltaBinario implements AtaqueInterface {
  private readonly tamanhoMaximo: number;

  constructor({ tamanhoMaximo = 256 }: { tamanhoMaximo?: number } = {}) {
    this.tamanhoMaximo = tamanhoMaximo;
  }

  nome(): string {
    return 'Ida-e-volta com dados binários (inclui NUL)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const falhas: (number | string)[] = [];

    for (let len = 0; len <= this.tamanhoMaximo; len++) {
      const texto = len === 0 ? Buffer.alloc(0) : randomBytes(len);
      try {
        if (alvo.decrypt(alvo.encrypt(texto)) !== texto.toString('utf8')) {
          falhas.push(len);
        }
      } catch (e) {
        const mensagem = e instanceof Error ? e.message : String(e);
        falhas.push(`${len} (erro: ${mensagem})`);
      }
    }

    const todos = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    if (alvo.decrypt(alvo.encrypt(todos)) !== todos.toString('utf8')) {
      falhas.push('todos os 256 valores de byte');
    }

    if (falhas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        'Falhou em ' + falhas.length + ' caso(s): ' + falhas.slice(0, 10).join(', '),
        { falhas },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todos os tamanhos 0..${this.tamanhoMaximo} e os 256 valores de byte preservados`,
    );
  }
}

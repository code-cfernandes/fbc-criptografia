import type { AlvoCriptografico } from './AlvoCriptografico.ts';
import type { ResultadoAtaque } from './ResultadoAtaque.ts';

export interface AtaqueInterface {
  nome(): string;

  /**
   * Roda o ataque contra o alvo e retorna o resultado.
   * Deve lançar SkipAtaqueException se o alvo não suportar os recursos
   * necessários (ex: não expõe gerarKeystreamBruto).
   */
  executar(alvo: AlvoCriptografico): ResultadoAtaque;
}

export type Severidade =
  | 'critica'
  | 'alta'
  | 'media'
  | 'baixa'
  | 'info'
  | 'pulado'
  | 'demonstracao'
  | 'erro';

/**
 * Resultado de rodar um ataque contra um alvo.
 *
 * `vulneravel = true` significa que o ataque ACHOU um problema (a cifra falhou).
 * `vulneravel = false` significa que a cifra resistiu a esse ataque específico.
 */
export class ResultadoAtaque {
  readonly nomeAtaque: string;
  readonly vulneravel: boolean;
  readonly severidade: Severidade;
  readonly detalhes: string;
  readonly dados: Record<string, unknown> | null;

  constructor(
    nomeAtaque: string,
    vulneravel: boolean,
    severidade: Severidade,
    detalhes: string,
    dados: Record<string, unknown> | null = null,
  ) {
    this.nomeAtaque = nomeAtaque;
    this.vulneravel = vulneravel;
    this.severidade = severidade;
    this.detalhes = detalhes;
    this.dados = dados;
  }

  linhaResumo(): string {
    let status: string;
    if (this.severidade === 'pulado') {
      status = 'PULADO';
    } else if (this.severidade === 'demonstracao') {
      status = 'DEMONSTRAÇÃO';
    } else {
      status = this.vulneravel ? '❌ VULNERÁVEL' : '✅ resistiu';
    }

    return `[${status}] ${this.nomeAtaque} (${this.severidade}): ${this.detalhes}`;
  }
}

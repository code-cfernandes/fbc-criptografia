/** Lançada quando o alvo não suporta os recursos que um ataque precisa. */
export class SkipAtaqueException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SkipAtaqueException';
  }
}

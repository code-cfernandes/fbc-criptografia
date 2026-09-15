'use strict';

/** Lançada quando o alvo não suporta os recursos que um ataque precisa. */
class SkipAtaqueException extends Error {
  constructor(message) {
    super(message);
    this.name = 'SkipAtaqueException';
  }
}

module.exports = SkipAtaqueException;

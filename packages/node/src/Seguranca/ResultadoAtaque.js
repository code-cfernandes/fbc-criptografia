'use strict';

/**
 * Resultado de rodar um ataque contra um alvo.
 *
 * `vulneravel = true` significa que o ataque ACHOU um problema (a cifra falhou).
 * `vulneravel = false` significa que a cifra resistiu a esse ataque específico.
 */
class ResultadoAtaque {
  constructor(nomeAtaque, vulneravel, severidade, detalhes, dados = null) {
    this.nomeAtaque = nomeAtaque;
    this.vulneravel = vulneravel;
    this.severidade = severidade;
    this.detalhes = detalhes;
    this.dados = dados;
  }

  linhaResumo() {
    let status;
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

module.exports = ResultadoAtaque;

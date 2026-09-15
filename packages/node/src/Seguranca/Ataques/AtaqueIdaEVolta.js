'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');

/**
 * Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
 * de decrypt precisa devolver o texto original, em qualquer tamanho.
 * Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
 * segurança mais sério por trás (foi assim em quase todas as rodadas
 * anteriores dessa conversa).
 */
class AtaqueIdaEVolta {
  constructor({ tamanhoMaximo = 130 } = {}) {
    this.tamanhoMaximo = tamanhoMaximo;
  }

  nome() {
    return 'Ida-e-volta (round trip)';
  }

  executar(alvo) {
    const falhas = [];
    for (let len = 0; len <= this.tamanhoMaximo; len++) {
      const texto = 'Q'.repeat(len);
      try {
        const token = alvo.encrypt(texto);
        const decifrado = alvo.decrypt(token);
        if (decifrado !== texto) {
          falhas.push(len);
        }
      } catch (e) {
        falhas.push(`${len} (erro: ${e.message})`);
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

module.exports = AtaqueIdaEVolta;

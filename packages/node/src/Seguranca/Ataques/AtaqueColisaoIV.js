'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const CriptografiaAlvo = require('../CriptografiaAlvo.js');

/**
 * Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
 * garantias de confidencialidade (keystream reusado = "two-time pad").
 * Gera muitos tokens do MESMO texto e verifica se os IVs nunca colidem.
 */
class AtaqueColisaoIV {
  constructor({ geracoes = 5000 } = {}) {
    this.geracoes = geracoes;
  }

  nome() {
    return 'Colisão de IV';
  }

  executar(alvo) {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    const vistos = new Set();
    let colisoes = 0;

    for (let i = 0; i < this.geracoes; i++) {
      const token = alvo.encrypt('MESMO_TEXTO_SEMPRE');
      const decodificado = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
      const iv = alvo.decompor(decodificado).iv;
      const chaveIv = iv.toString('hex');
      if (vistos.has(chaveIv)) {
        colisoes++;
      }
      vistos.add(chaveIv);
    }

    if (colisoes > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `${colisoes} colisão(ões) de IV em ${this.geracoes} gerações`,
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `0 colisões em ${this.geracoes} gerações`,
    );
  }
}

module.exports = AtaqueColisaoIV;

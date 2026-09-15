'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');

/**
 * As primeiras versões dessa cifra tinham um header fixo (43 bytes idênticos
 * sempre) ou um marcador constante (o '$' na posição 64). Esse ataque gera
 * vários tokens de textos diferentes e procura qualquer posição de byte que
 * NUNCA muda - isso é uma âncora que um atacante pode usar pra recuperar a
 * chave (como fizemos na primeira rodada dessa conversa).
 */
class AtaqueBytesFixos {
  constructor({ amostras = 30 } = {}) {
    this.amostras = amostras;
  }

  nome() {
    return 'Bytes fixos entre tokens';
  }

  executar(alvo) {
    const tokens = [];
    for (let i = 0; i < this.amostras; i++) {
      const texto = 'TEXTO_VARIADO_' + i + String.fromCharCode(65 + (i % 26)).repeat(i % 10);
      tokens.push(alvo.encrypt(texto).slice(alvo.prefixo().length));
    }

    const decodificados = tokens.map((t) => alvo.base64urlDecode(t));
    const tamanhoMinimo = Math.min(...decodificados.map((d) => d.length));

    const posicoesFixas = [];
    for (let i = 0; i < tamanhoMinimo; i++) {
      const valores = new Set(decodificados.map((d) => d[i]));
      if (valores.size === 1) {
        posicoesFixas.push(i);
      }
    }

    if (posicoesFixas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'alta',
        `${posicoesFixas.length} posição(ões) de byte fixas em ${this.amostras} tokens: ` +
          posicoesFixas.slice(0, 10).join(', '),
        { posicoes: posicoesFixas },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `0 de ${tamanhoMinimo} posições fixas em ${this.amostras} tokens`,
    );
  }
}

module.exports = AtaqueBytesFixos;

'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const { randomBytes } = require('../Util.js');

/**
 * Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
 * sincronização de bloco, repetição de keystream em blocos distantes ou
 * perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
 * curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
 * gera tokens diferentes.
 *
 * Adaptação Node: os dados são Buffers; como decrypt() devolve string
 * (UTF-8), comparamos com a representação UTF-8 dos mesmos bytes.
 */
class AtaqueMensagemLonga {
  constructor({ tamanhos = [1000, 10000, 100000] } = {}) {
    this.tamanhos = tamanhos;
  }

  nome() {
    return 'Mensagens longas (multi-bloco)';
  }

  executar(alvo) {
    const falhas = [];

    for (const t of this.tamanhos) {
      const texto = randomBytes(t);
      try {
        const token = alvo.encrypt(texto);
        if (alvo.decrypt(token) !== texto.toString('utf8')) {
          falhas.push(`${t} bytes (conteúdo diferente)`);
        }
      } catch (e) {
        falhas.push(`${t} bytes (erro: ${e.message})`);
      }
    }

    const texto = 'A'.repeat(1000);
    const t1 = alvo.encrypt(texto);
    const t2 = alvo.encrypt(texto);
    if (t1 === t2) {
      falhas.push('tokens idênticos para o mesmo texto (IV não varia)');
    }

    if (falhas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        'Falha em: ' + falhas.join('; '),
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      'Ida-e-volta OK em ' +
        this.tamanhos.join(', ') +
        ' bytes; mesmo texto gera tokens distintos',
    );
  }
}

module.exports = AtaqueMensagemLonga;

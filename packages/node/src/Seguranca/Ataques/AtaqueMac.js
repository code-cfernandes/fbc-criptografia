'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');

/**
 * Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
 * (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
 * Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
 */
class AtaqueMac {
  constructor({ mensagem = 'mensagem para o ataque de MAC' } = {}) {
    this.mensagem = mensagem;
  }

  nome() {
    return 'Força bruta e truncamento do MAC';
  }

  executar(alvo) {
    const token = alvo.encrypt(this.mensagem);
    const decoded = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
    const campos = alvo.decompor(decoded);

    const montar = (integridade) =>
      alvo.prefixo() +
      alvo.base64urlEncode(
        alvo.recompor({ integridade, ciphertext: campos.ciphertext, iv: campos.iv }),
      );

    const aceitos = [];

    // 1) integridade zerada
    try {
      alvo.decrypt(montar(Buffer.alloc(campos.integridade.length, 0x00)));
      aceitos.push('integridade zerada');
    } catch (e) {
      // esperado
    }

    // 2) integridade truncada pela metade
    try {
      alvo.decrypt(montar(Buffer.from(campos.integridade.subarray(0, 16))));
      aceitos.push('integridade truncada (16 bytes)');
    } catch (e) {
      // esperado
    }

    // 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
    // que reconstruiria o próprio token válido e não é uma forja)
    const base = Buffer.from(campos.integridade);
    for (let v = 0; v < 256; v++) {
      if (v === base[0]) continue;
      const tentativa = Buffer.from(base);
      tentativa[0] = v;
      try {
        alvo.decrypt(montar(tentativa));
        aceitos.push(`byte 0 do MAC = ${v}`);
      } catch (e) {
        // esperado
      }
    }

    const vulneravel = aceitos.length > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      vulneravel
        ? `${aceitos.length} variante(s) de MAC aceitas: ${aceitos.slice(0, 5).join('; ')}`
        : 'Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita',
      { aceitos },
    );
  }
}

module.exports = AtaqueMac;

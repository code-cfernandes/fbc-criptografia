'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const { randomBytes } = require('../Util.js');

/**
 * Robustez do parser de tokens: qualquer entrada que não seja um token
 * íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
 * devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
 * é uma porta pra bugs de validação e "token smuggling".
 */
class AtaqueTokensMalformados {
  nome() {
    return 'Tokens malformados (fuzzing de entrada)';
  }

  executar(alvo) {
    const token = alvo.encrypt('MENSAGEM_VALIDA_PARA_TESTE');
    const prefixo = alvo.prefixo();
    const corpo = token.slice(prefixo.length);

    const casos = {
      vazio: '',
      'só prefixo': prefixo,
      'prefixo errado': 'XXX' + corpo,
      'base64 inválido': prefixo + '!!!@@@###',
      'bytes extras no fim': token + 'AAAA',
      'bytes extras no início': 'AAAA' + token,
    };
    for (let len = 1; len < token.length; len++) {
      casos[`truncado em ${len}`] = token.slice(0, len);
    }
    for (let i = 0; i < 20; i++) {
      casos[`lixo aleatório ${i}`] = prefixo + randomBytes(16).toString('hex');
    }

    const aceitos = [];
    for (const [nome, t] of Object.entries(casos)) {
      try {
        const r = alvo.decrypt(t);
        aceitos.push(`${nome} -> aceito (retornou ${Buffer.byteLength(r, 'utf8')} bytes)`);
      } catch (e) {
        // comportamento esperado
      }
    }

    if (aceitos.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `${aceitos.length} entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas`,
        { exemplos: aceitos.slice(0, 10) },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${Object.keys(casos).length} entradas malformadas foram rejeitadas`,
    );
  }
}

module.exports = AtaqueTokensMalformados;

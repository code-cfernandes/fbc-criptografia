'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const CriptografiaAlvo = require('../CriptografiaAlvo.js');
const { randomInt, arrayRandKey } = require('../Util.js');

/**
 * O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
 * token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
 * sucesso", a cifra não está autenticando o conteúdo - é a falha que
 * encontramos e corrigimos várias vezes ao longo dessa conversa.
 */
class AtaqueAdulteracao {
  constructor({ tentativas = 500 } = {}) {
    this.tentativas = tentativas;
  }

  nome() {
    return 'Adulteração de bits (integridade)';
  }

  executar(alvo) {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
    }

    const aceitosIndevidamente = [];

    for (let t = 0; t < this.tentativas; t++) {
      const texto = `MSG_${t}` + 'X'.repeat(randomInt(0, 50));
      const token = alvo.encrypt(texto);
      const decodificado = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
      const campos = alvo.decompor(decodificado);

      const nomeCampo = arrayRandKey(campos);
      const valor = Buffer.from(campos[nomeCampo]);
      if (valor.length === 0) {
        continue;
      }
      const pos = randomInt(0, valor.length - 1);
      valor[pos] = valor[pos] ^ (1 << randomInt(0, 7));
      campos[nomeCampo] = valor;

      const tokenAdulterado = alvo.prefixo() + alvo.base64urlEncode(alvo.recompor(campos));

      try {
        const resultado = alvo.decrypt(tokenAdulterado);
        aceitosIndevidamente.push(
          `campo=${nomeCampo}, texto original=${texto}, resultado aceito=${resultado}`,
        );
      } catch (e) {
        // esperado - a adulteração deveria ser rejeitada
      }
    }

    if (aceitosIndevidamente.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `${aceitosIndevidamente.length} de ${this.tentativas} tokens adulterados foram ACEITOS`,
        { exemplos: aceitosIndevidamente.slice(0, 5) },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${this.tentativas} adulterações foram rejeitadas`,
    );
  }
}

module.exports = AtaqueAdulteracao;

'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');

/**
 * Length extension / truncamento: a estrutura do token é
 * integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
 * Truncar, estender ou deslocar bytes não pode produzir um token aceito.
 */
class AtaqueLengthExtension {
  constructor({ mensagem = 'texto para o ataque de length extension' } = {}) {
    this.mensagem = mensagem;
  }

  nome() {
    return 'Length extension / truncamento de token';
  }

  executar(alvo) {
    const prefixo = alvo.prefixo();
    const token = alvo.encrypt(this.mensagem);
    const corpo = token.slice(prefixo.length);
    const meio = Math.floor(corpo.length / 2);

    const variantes = {
      'append A': prefixo + corpo + 'A',
      'append =': prefixo + corpo + '=',
      'truncar 1 char': prefixo + corpo.slice(0, -1),
      'truncar 2 chars': prefixo + corpo.slice(0, -2),
      'inserir ! no meio': prefixo + corpo.slice(0, meio) + '!' + corpo.slice(meio),
      'prefixo extra': prefixo + 'A' + corpo,
    };

    // variantes que mexem nos campos decodificados
    try {
      const decoded = alvo.base64urlDecode(corpo);
      const campos = alvo.decompor(decoded);

      const ctMaior = Buffer.concat([campos.ciphertext, Buffer.from([0x41])]);
      variantes['ciphertext +1 byte'] =
        prefixo +
        alvo.base64urlEncode(
          alvo.recompor({ integridade: campos.integridade, ciphertext: ctMaior, iv: campos.iv }),
        );

      const ctMenor = Buffer.from(
        campos.ciphertext.subarray(0, Math.max(0, campos.ciphertext.length - 1)),
      );
      variantes['ciphertext -1 byte'] =
        prefixo +
        alvo.base64urlEncode(
          alvo.recompor({ integridade: campos.integridade, ciphertext: ctMenor, iv: campos.iv }),
        );

      const ivMaior = Buffer.concat([campos.iv, Buffer.from([0x42])]);
      variantes['iv +1 byte'] =
        prefixo +
        alvo.base64urlEncode(
          alvo.recompor({ integridade: campos.integridade, ciphertext: campos.ciphertext, iv: ivMaior }),
        );
    } catch (e) {
      // se a decodificação falhar, segue com as variantes textuais
    }

    const aceitas = [];
    for (const nome of Object.keys(variantes)) {
      const v = variantes[nome];
      if (v === token) continue;
      try {
        alvo.decrypt(v);
        aceitas.push(nome);
      } catch (e) {
        // esperado
      }
    }

    const vulneravel = aceitas.length > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      vulneravel
        ? `${aceitas.length} variante(s) aceita(s): ${aceitas.join('; ')}`
        : `Todas as ${Object.keys(variantes).length} variantes de truncamento/extensão foram rejeitadas`,
      { aceitas },
    );
  }
}

module.exports = AtaqueLengthExtension;

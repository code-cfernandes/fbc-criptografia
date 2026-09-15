'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const CriptografiaAlvo = require('../CriptografiaAlvo.js');

/**
 * Um mesmo token não deveria ter múltiplas representações textuais válidas.
 * Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
 * padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
 * lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
 * token. Isso é "token smuggling": sistemas que comparam/usam a string do
 * token de formas diferentes (cache, WAF, deduplicação/replay) discordam
 * sobre o que ele significa.
 */
class AtaqueCanonicalizacaoToken {
  nome() {
    return 'Canonicalização do token (base64 não-canônico)';
  }

  executar(alvo) {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
    }

    const texto = 'MENSAGEM_DE_TESTE_DE_CANONICALIZACAO';
    const token = alvo.encrypt(texto);
    const prefixo = alvo.prefixo();
    const corpo = token.slice(prefixo.length);
    const meio = Math.trunc(corpo.length / 2);

    const variantes = {};
    for (const p of [0, meio, corpo.length - 1]) {
      variantes[`espaço na posição ${p}`] = prefixo + corpo.slice(0, p) + ' ' + corpo.slice(p);
      variantes[`newline na posição ${p}`] = prefixo + corpo.slice(0, p) + '\n' + corpo.slice(p);
      variantes[`tab na posição ${p}`] = prefixo + corpo.slice(0, p) + '\t' + corpo.slice(p);
    }
    variantes['alfabeto padrão (+/)'] = prefixo + corpo.replace(/-/g, '+').replace(/_/g, '/');
    variantes['padding "=" extra'] = prefixo + corpo + '=';
    variantes['caractere inválido no meio'] =
      prefixo + corpo.slice(0, meio) + '!' + corpo.slice(meio);

    const aceitas = [];
    for (const [nome, v] of Object.entries(variantes)) {
      if (v === token) {
        continue;
      }
      try {
        if (alvo.decrypt(v) === texto) {
          aceitas.push(nome);
        }
      } catch (e) {
        // esperado
      }
    }

    if (aceitas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'media',
        `${aceitas.length} variante(s) textualmente diferente(s) decifram para o mesmo texto: ${aceitas.join('; ')}`,
        { variantes_aceitas: aceitas },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todas as ${Object.keys(variantes).length} variantes não-canônicas foram rejeitadas`,
    );
  }
}

module.exports = AtaqueCanonicalizacaoToken;

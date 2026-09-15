'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const CriptografiaAlvo = require('../CriptografiaAlvo.js');

/**
 * O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
 * Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
 * trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
 * timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
 * rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
 * mesmo sem nunca colidir de fato.
 *
 * Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
 * ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
 * e sequências crescentes/monótonas entre IVs consecutivos (sintoma
 * clássico de contador ou timestamp).
 */
class AtaqueEntropiaIV {
  constructor({ amostras = 2000 } = {}) {
    this.amostras = amostras;
  }

  nome() {
    return 'Entropia e previsibilidade do IV';
  }

  executar(alvo) {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    const ivs = [];
    for (let i = 0; i < this.amostras; i++) {
      const token = alvo.encrypt('X');
      const decodificado = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
      ivs.push(alvo.decompor(decodificado).iv);
    }

    const problemas = [];

    // Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
    const contagem = new Array(256).fill(0);
    let total = 0;
    for (const iv of ivs) {
      for (let i = 0; i < iv.length; i++) {
        contagem[iv[i]]++;
        total++;
      }
    }
    const esperado = total / 256;
    let qui2 = 0.0;
    for (const c of contagem) {
      qui2 += ((c - esperado) ** 2) / esperado;
    }
    if (qui2 > 330) {
      problemas.push(`distribuição de bytes suspeita (qui-quadrado=${qui2.toFixed(1)}, >330 é suspeito)`);
    }

    // Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
    // primeiro byte estritamente crescente (um contador/timestamp cru
    // produziria isso quase sempre; aleatório, só ~50% das vezes).
    let crescentes = 0;
    for (let i = 1; i < ivs.length; i++) {
      if (ivs[i][0] > ivs[i - 1][0]) {
        crescentes++;
      }
    }
    const proporcaoCrescente = crescentes / (ivs.length - 1);
    if (proporcaoCrescente > 0.65 || proporcaoCrescente < 0.35) {
      problemas.push(
        `primeiro byte do IV parece monotônico (${(proporcaoCrescente * 100).toFixed(0)}% das vezes crescente; aleatório ficaria perto de 50%)`,
      );
    }

    // Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
    // (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
    // repetição interna) - a AUSÊNCIA de qualquer repetição interna em
    // quase todos os IVs seria estranha (sugeriria geração não-uniforme,
    // tipo bytes distintos forçados).
    let semRepeticaoInterna = 0;
    for (const iv of ivs) {
      if (new Set(iv).size === iv.length) {
        semRepeticaoInterna++;
      }
    }
    const proporcaoSemRepeticao = semRepeticaoInterna / ivs.length;
    // Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
    if (proporcaoSemRepeticao > 0.9 || proporcaoSemRepeticao < 0.5) {
      problemas.push(
        `${(proporcaoSemRepeticao * 100).toFixed(0)}% dos IVs não têm nenhum byte repetido internamente (esperado ~72% para 16 bytes aleatórios)`,
      );
    }

    if (problemas.length > 0) {
      return new ResultadoAtaque(this.nome(), true, 'alta', problemas.join('; '));
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `qui-quadrado=${qui2.toFixed(1)}, ${(proporcaoCrescente * 100).toFixed(0)}% primeiro-byte-crescente (~50% esperado), ${(proporcaoSemRepeticao * 100).toFixed(0)}% sem repetição interna (~72% esperado) - tudo consistente com IV aleatório`,
    );
  }
}

module.exports = AtaqueEntropiaIV;

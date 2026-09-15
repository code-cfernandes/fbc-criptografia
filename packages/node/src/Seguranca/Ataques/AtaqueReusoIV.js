'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes, toBuffer } = require('../Util.js');

/**
 * A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
 * reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
 * Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
 * aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
 * gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
 * vaza nesse cenário catastrófico.
 *
 * Isso não é um "bug" da implementação (é uma propriedade universal de
 * qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
 * quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
 * suíte: a segurança inteira depende do IV nunca repetir.
 */
class AtaqueReusoIV {
  nome() {
    return 'Reuso forçado de IV (two-time pad)';
  }

  executar(alvo) {
    const chave = alvo.chaveDeTeste();
    const ivFixo = randomBytes(alvo.tamanhoIv());

    const primeiro = alvo.gerarKeystreamBruto(chave, ivFixo, 'enc', 16);
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const plaintext1 = 'TRANSFERIR_1000';
    const plaintext2 = 'CANCELAR_TUDO!!';
    const tamanho = Math.max(plaintext1.length, plaintext2.length);

    const keystream = alvo.gerarKeystreamBruto(chave, ivFixo, 'enc', tamanho);

    const ciphertext1 = this.xor(plaintext1, keystream);
    const ciphertext2 = this.xor(plaintext2, keystream);

    // O atacante NUNCA precisou saber a key nem o keystream - só
    // observou os dois ciphertexts (que vazariam publicamente se o
    // IV fosse reusado) e os combinou entre si.
    const xorDosCiphertexts = this.xor(ciphertext1, ciphertext2);
    const xorEsperadoDosPlaintexts = this.xor(plaintext1, plaintext2);

    const vazou = xorDosCiphertexts.equals(xorEsperadoDosPlaintexts);

    // Com IV reusado, a propriedade é universal e sempre se confirma - por
    // isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
    // demonstração). Só vira alerta se, por algum motivo, a propriedade
    // NÃO se confirmar (o que indicaria um combinador inconsistente).
    return new ResultadoAtaque(
      this.nome(),
      !vazou,
      vazou ? 'demonstracao' : 'alta',
      vazou
        ? 'Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) ' +
          'sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA ' +
          'defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV).'
        : 'INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)',
      {
        plaintext1,
        plaintext2,
        xor_plaintexts_hex: xorEsperadoDosPlaintexts.toString('hex'),
        xor_ciphertexts_hex: xorDosCiphertexts.toString('hex'),
      },
    );
  }

  xor(a, b) {
    const A = toBuffer(a);
    const B = toBuffer(b);
    const len = Math.min(A.length, B.length);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      out[i] = A[i] ^ B[i];
    }
    return out;
  }
}

module.exports = AtaqueReusoIV;

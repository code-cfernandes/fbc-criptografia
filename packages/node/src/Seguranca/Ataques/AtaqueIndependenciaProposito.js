'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes, bitsDiferentes } = require('../Util.js');

/**
 * A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
 * chave do MAC ('mac'). Se os dois streams não forem independentes, um
 * atacante que recupere o keystream de dados (ataque de texto conhecido)
 * pode derivar a chave do MAC e FORJAR tokens válidos.
 *
 * O teste procura dois sintomas de acoplamento:
 *  1. a distância de Hamming média entre os streams deve ser ~50%;
 *  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
 *     uma máscara fixa, o mac é 100% previsível a partir do enc.
 */
class AtaqueIndependenciaProposito {
  constructor({ amostras = 2000, tamanho = 32 } = {}) {
    this.amostras = amostras;
    this.tamanho = tamanho;
  }

  nome() {
    return 'Independência entre keystreams de propósitos diferentes (enc x mac)';
  }

  executar(alvo) {
    const primeiro = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanho,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const distancias = [];
    const mascaras = new Set();
    for (let i = 0; i < this.amostras; i++) {
      const chave = randomBytes(alvo.chaveDeTeste().length);
      const iv = randomBytes(alvo.tamanhoIv());

      const enc = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanho);
      const mac = alvo.gerarKeystreamBruto(chave, iv, 'mac', this.tamanho);

      distancias.push(bitsDiferentes(enc, mac) / (this.tamanho * 8));
      mascaras.add(this.xorBytes(enc, mac).toString('hex'));
    }

    const media = distancias.reduce((acc, v) => acc + v, 0) / distancias.length;
    const mascarasDistintas = mascaras.size;

    const vulneravel = media < 0.4 || media > 0.6 || mascarasDistintas < this.amostras;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      `Hamming médio enc x mac=${(media * 100).toFixed(1)}% (esperado ~50%); ${mascarasDistintas} máscara(s) XOR distinta(s) em ${this.amostras} amostras${
        mascarasDistintas < this.amostras
          ? ' - MÁSCARA REPETIDA: mac previsível a partir de enc!'
          : ''
      }`,
      { media, mascaras_distintas: mascarasDistintas },
    );
  }

  xorBytes(a, b) {
    const len = Math.min(a.length, b.length);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

module.exports = AtaqueIndependenciaProposito;

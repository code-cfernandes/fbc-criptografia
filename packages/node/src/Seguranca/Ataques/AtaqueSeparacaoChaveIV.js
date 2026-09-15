'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
 * Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
 * resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
 *
 *     keystream(key, iv) == keystream(key ^ d, iv ^ d)
 *
 * para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
 * propriedade estrutural relevante: significa que key e iv não entram de
 * forma independente na cifra, o que enfraquece o modelo de segurança (o IV
 * deveria contribuir com entropia própria, não só deslocar a chave por XOR).
 */
class AtaqueSeparacaoChaveIV {
  constructor({ tentativas = 50, tamanhoBloco = 32 } = {}) {
    this.tentativas = tentativas;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome() {
    return 'Separação chave/IV (invariância a key XOR iv)';
  }

  executar(alvo) {
    const tamChave = Buffer.byteLength(alvo.chaveDeTeste(), 'utf8');
    const tamIv = alvo.tamanhoIv();

    const primeiro = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(tamIv),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    let confirmacoes = 0;
    for (let t = 0; t < this.tentativas; t++) {
      const chave = randomBytes(tamChave);
      const iv = randomBytes(tamIv);
      const d = randomBytes(tamIv);

      const chave2 = Buffer.alloc(tamChave);
      for (let p = 0; p < tamChave; p++) {
        chave2[p] = chave[p] ^ d[p % tamIv];
      }
      const iv2 = Buffer.alloc(tamIv);
      for (let p = 0; p < tamIv; p++) {
        iv2[p] = iv[p] ^ d[p];
      }

      const ks1 = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanhoBloco);
      const ks2 = alvo.gerarKeystreamBruto(chave2, iv2, 'enc', this.tamanhoBloco);

      if (ks1.equals(ks2)) {
        confirmacoes++;
      }
    }

    const invariante = confirmacoes === this.tentativas;

    return new ResultadoAtaque(
      this.nome(),
      invariante,
      invariante ? 'media' : 'info',
      invariante
        ? `Confirmado em ${this.tentativas}/${this.tentativas}: keystream(key,iv) == keystream(key^d, iv^d). ` +
          'O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule.'
        : `Invariância não se confirmou (${confirmacoes}/${this.tentativas}); key e iv entram de forma independente.`,
      { confirmacoes, tentativas: this.tentativas },
    );
  }
}

module.exports = AtaqueSeparacaoChaveIV;

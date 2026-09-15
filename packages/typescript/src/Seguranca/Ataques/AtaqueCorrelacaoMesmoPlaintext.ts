import { CriptografiaAlvo } from '../CriptografiaAlvo.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { contarBits1, randomInt } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

interface OpcoesCorrelacaoMesmoPlaintext {
  amostras?: number;
  textoFixo?: string;
}

/**
 * O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
 * Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
 * venham do mesmo texto, se comportam como se fossem de textos diferentes
 * (distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).
 *
 * Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
 * parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
 * cifrar 500 textos diferentes.
 */
export class AtaqueCorrelacaoMesmoPlaintext implements AtaqueInterface {
  private readonly amostras: number;
  private readonly textoFixo: string;

  constructor({
    amostras = 300,
    textoFixo = 'MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR',
  }: OpcoesCorrelacaoMesmoPlaintext = {}) {
    this.amostras = amostras;
    this.textoFixo = textoFixo;
  }

  nome(): string {
    return 'Correlação entre ciphertexts do mesmo plaintext';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_decode do alvo.');
    }

    const ciphertexts: Buffer[] = [];
    for (let i = 0; i < this.amostras; i++) {
      const token = alvo.encrypt(this.textoFixo);
      const decodificado = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
      ciphertexts.push(alvo.decompor(decodificado).ciphertext);
    }

    // Compara pares aleatórios de ciphertexts (não todos contra todos,
    // pra manter o custo baixo) e mede a distância de Hamming média.
    const comparacoes = Math.min(500, Math.trunc((this.amostras * (this.amostras - 1)) / 2));
    const distancias: number[] = [];
    for (let c = 0; c < comparacoes; c++) {
      const i = randomInt(0, this.amostras - 1);
      const j = randomInt(0, this.amostras - 1);
      if (i === j) {
        continue;
      }
      distancias.push(this.distanciaHammingRelativa(ciphertexts[i], ciphertexts[j]));
    }

    const media = distancias.reduce((acc, v) => acc + v, 0) / distancias.length;

    // Também confere que nenhum PAR de ciphertexts é idêntico (o que
    // indicaria reuso de IV+key, capturado de outro ângulo).
    const unicos = new Set(ciphertexts.map((b) => b.toString('hex')));
    const duplicatas = ciphertexts.length - unicos.size;

    const vulneravel = media < 0.4 || media > 0.6 || duplicatas > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'alta' : 'info',
      `distância de Hamming média entre ciphertexts do mesmo texto: ${(media * 100).toFixed(1)}% (esperado ~50%), ${duplicatas} duplicata(s) exata(s) em ${this.amostras} amostras`,
      { media, duplicatas },
    );
  }

  distanciaHammingRelativa(a: Buffer, b: Buffer): number {
    const len = Math.min(a.length, b.length);
    if (len === 0) {
      return 0.5;
    }
    let diff = 0;
    for (let i = 0; i < len; i++) {
      diff += contarBits1(a[i] ^ b[i]);
    }
    return diff / (len * 8);
  }
}

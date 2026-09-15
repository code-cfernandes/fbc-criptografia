import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';

/**
 * Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
 * (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
 * Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
 */
export class AtaqueMac implements AtaqueInterface {
  private readonly mensagem: string;

  constructor({ mensagem = 'mensagem para o ataque de MAC' }: { mensagem?: string } = {}) {
    this.mensagem = mensagem;
  }

  nome(): string {
    return 'Força bruta e truncamento do MAC';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const token = alvo.encrypt(this.mensagem);
    const decoded = alvo.base64urlDecode(token.slice(alvo.prefixo().length));
    const campos = alvo.decompor(decoded);

    const montar = (integridade: Buffer): string =>
      alvo.prefixo() +
      alvo.base64urlEncode(alvo.recompor({ integridade, ciphertext: campos.ciphertext, iv: campos.iv }));

    const aceitos: string[] = [];

    // 1) integridade zerada
    try {
      alvo.decrypt(montar(Buffer.alloc(campos.integridade.length, 0x00)));
      aceitos.push('integridade zerada');
    } catch {
      // esperado
    }

    // 2) integridade truncada pela metade
    try {
      alvo.decrypt(montar(Buffer.from(campos.integridade.subarray(0, 16))));
      aceitos.push('integridade truncada (16 bytes)');
    } catch {
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
      } catch {
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

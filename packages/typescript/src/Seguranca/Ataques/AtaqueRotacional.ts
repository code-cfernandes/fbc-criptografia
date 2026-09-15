import { randomBytes } from '../Util.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';

function rotacionar(buf: Buffer, k: number): Buffer {
  const n = buf.length;
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    out[i] = buf[(i + k) % n];
  }
  return out;
}

/**
 * Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
 * de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
 * `keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
 * byte e também coincidência direta do keystream.
 */
export class AtaqueRotacional implements AtaqueInterface {
  private readonly tamanho: number;

  constructor({ tamanho = 64 }: { tamanho?: number } = {}) {
    this.tamanho = tamanho;
  }

  nome(): string {
    return 'Rotacional/slide (simetria por rotação)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const chave = Buffer.from(alvo.chaveDeTeste(), 'utf8');
    const iv = randomBytes(alvo.tamanhoIv());
    const ks1 = alvo.gerarKeystreamBruto(chave, iv, 'enc', this.tamanho);

    const coincidencias: string[] = [];
    for (let k = 1; k < chave.length; k++) {
      const ks2 = alvo.gerarKeystreamBruto(
        rotacionar(chave, k),
        rotacionar(iv, k),
        'enc',
        this.tamanho,
      );

      if (ks2.equals(ks1)) {
        coincidencias.push(`rotação ${k}: keystream idêntico`);
        continue;
      }
      // metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
      const alvoRot = rotacionar(ks1.subarray(0, 32), k);
      if (ks2.subarray(0, 32).equals(alvoRot)) {
        coincidencias.push(`rotação ${k}: keystream rotacionado`);
      }
    }

    const vulneravel = coincidencias.length > 0;

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'critica' : 'info',
      vulneravel
        ? `Simetria rotacional encontrada: ${coincidencias.slice(0, 5).join('; ')}`
        : `Nenhuma das ${chave.length - 1} rotações de byte reproduziu o keystream`,
      { coincidencias },
    );
  }
}

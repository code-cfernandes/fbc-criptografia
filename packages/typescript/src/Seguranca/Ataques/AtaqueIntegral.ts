import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';
import { randomBytes } from '../Util.ts';
import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';

/**
 * Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
 * um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
 *
 * Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
 * soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
 * a saída como função do byte variado fica "quase bijetiva" e a soma tende a
 * zero MUITO mais que o acaso - um distinguisher clássico.
 *
 * Como uma única (chave, IV) tem variância alta, acumula várias tentativas
 * para estimar o viés de forma estável (comparado a p=1/256).
 */
export class AtaqueIntegral implements AtaqueInterface {
  private readonly tamanhoBloco: number;
  private readonly posicoesIv: number;
  private readonly posicoesChave: number;
  private readonly tentativas: number;
  private readonly limiteZ: number;

  constructor({
    tamanhoBloco = 32,
    posicoesIv = 8,
    posicoesChave = 8,
    tentativas = 16,
    limiteZ = 5.0,
  }: {
    tamanhoBloco?: number;
    posicoesIv?: number;
    posicoesChave?: number;
    tentativas?: number;
    limiteZ?: number;
  } = {}) {
    this.tamanhoBloco = tamanhoBloco;
    this.posicoesIv = posicoesIv;
    this.posicoesChave = posicoesChave;
    this.tentativas = tentativas;
    this.limiteZ = limiteZ;
  }

  nome(): string {
    return 'Integral (soma balanceada variando 1 byte de IV/chave)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    const tamIv = alvo.tamanhoIv();
    const tamChave = alvo.chaveDeTeste().length;

    const primeiro = alvo.gerarKeystreamBruto(
      alvo.chaveDeTeste(),
      randomBytes(tamIv),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const distinguidores: string[] = [];
    let zerosTotal = 0;
    let bytesTotal = 0;

    for (let t = 0; t < this.tentativas; t++) {
      const chave = randomBytes(tamChave);
      const ivBase = randomBytes(tamIv);

      for (let pos = 0; pos < Math.min(this.posicoesIv, tamIv); pos++) {
        const [xor, zeros] = this.somarVariando(alvo, chave, ivBase, 'iv', pos);
        zerosTotal += zeros;
        bytesTotal += this.tamanhoBloco;
        if (this.todosZeros(xor)) {
          distinguidores.push(`iv[${pos}]`);
        }
      }

      for (let pos = 0; pos < Math.min(this.posicoesChave, tamChave); pos++) {
        const [xor, zeros] = this.somarVariando(alvo, chave, ivBase, 'key', pos);
        zerosTotal += zeros;
        bytesTotal += this.tamanhoBloco;
        if (this.todosZeros(xor)) {
          distinguidores.push(`key[${pos}]`);
        }
      }
    }

    const p = 1 / 256;
    const esperado = bytesTotal * p;
    const desvio = Math.sqrt(bytesTotal * p * (1 - p));
    const z = desvio > 0 ? (zerosTotal - esperado) / desvio : 0.0;

    const vulneravel = distinguidores.length > 0 || z > this.limiteZ;

    if (distinguidores.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        'Soma balanceada (XOR zero) encontrada variando: ' +
          distinguidores.slice(0, 10).join(', '),
        { distinguidores },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      vulneravel,
      vulneravel ? 'media' : 'info',
      `bytes de saída zerados=${zerosTotal} (esperado ~${esperado.toFixed(1)}, z=${z.toFixed(
        2,
      )}) em ${bytesTotal} amostras; limite z=${this.limiteZ.toFixed(1)}`,
      { zeros: zerosTotal, esperado, z },
    );
  }

  /** @returns XOR de 256 keystreams e quantos bytes deram zero */
  private somarVariando(
    alvo: AlvoCriptografico,
    chave: Buffer,
    ivBase: Buffer,
    campo: 'iv' | 'key',
    pos: number,
  ): [Buffer, number] {
    let xor: Buffer = Buffer.alloc(this.tamanhoBloco);
    for (let v = 0; v < 256; v++) {
      const k = Buffer.from(chave);
      const iv = Buffer.from(ivBase);
      if (campo === 'iv') {
        iv[pos] = v;
      } else {
        k[pos] = v;
      }
      const ks = alvo.gerarKeystreamBruto(k, iv, 'enc', this.tamanhoBloco);
      xor = this.xorBytes(xor, ks);
    }
    let zeros = 0;
    for (let i = 0; i < xor.length; i++) {
      if (xor[i] === 0) {
        zeros++;
      }
    }
    return [xor, zeros];
  }

  private todosZeros(buf: Buffer): boolean {
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] !== 0) {
        return false;
      }
    }
    return true;
  }

  private xorBytes(a: Buffer, b: Buffer): Buffer {
    const out = Buffer.alloc(a.length);
    for (let i = 0; i < a.length; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }
}

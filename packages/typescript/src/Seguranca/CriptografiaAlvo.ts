import { _internal, base64urlDecode, base64urlEncode, decrypt, encrypt } from '../Core/Criptografia.ts';
import type { AlvoCriptografico, CamposToken } from './AlvoCriptografico.ts';
import { toBuffer } from './Util.ts';

const CHAVE_PADRAO = 'pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf';

/**
 * Liga a suíte de ataques à classe Criptografia real, expondo as camadas
 * internas de keystream e checksum através do export `_internal`.
 */
export class CriptografiaAlvo implements AlvoCriptografico {
  private readonly chaveTeste: string;

  constructor(chaveTeste: string = CHAVE_PADRAO) {
    this.chaveTeste = chaveTeste;
    process.env.FBC_KEY = chaveTeste;
  }

  encrypt(texto: string | Buffer): string {
    return encrypt(texto);
  }

  decrypt(token: string): string {
    return decrypt(token);
  }

  prefixo(): string {
    return 'FBC';
  }

  decompor(tokenDecodificado: Buffer): CamposToken {
    const buf = toBuffer(tokenDecodificado);
    const tamIv = this.tamanhoIv();
    return {
      integridade: buf.subarray(0, 32),
      ciphertext: buf.subarray(32, buf.length - tamIv),
      iv: buf.subarray(buf.length - tamIv),
    };
  }

  recompor(campos: CamposToken): Buffer {
    return Buffer.concat([campos.integridade, campos.ciphertext, campos.iv]);
  }

  gerarKeystreamBruto(
    key: Buffer | string,
    iv: Buffer | string,
    proposito: string,
    tamanho: number,
  ): Buffer {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    const ivBuf = toBuffer(iv);
    return _internal.gerarKeystream(keyBuf, ivBuf, proposito, tamanho);
  }

  checksumBruto(dados: Buffer | string, key: Buffer | string): Buffer {
    return _internal.checksum(toBuffer(dados), toBuffer(key));
  }

  chaveDeTeste(): string {
    return this.chaveTeste;
  }

  tamanhoIv(): number {
    return 16;
  }

  base64urlDecode(data: string): Buffer {
    return base64urlDecode(data);
  }

  base64urlEncode(data: Buffer): string {
    return base64urlEncode(data);
  }
}

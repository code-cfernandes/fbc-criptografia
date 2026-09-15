'use strict';

const Criptografia = require('../Core/Criptografia.js');
const { toBuffer } = require('./Util.js');

/**
 * Liga a suíte de ataques à classe Criptografia real do Node, expondo as
 * camadas internas de keystream e checksum através do export `_internal`
 * (sem precisar de Reflection como no PHP).
 */
class CriptografiaAlvo {
  constructor(chaveTeste = 'pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf') {
    this._chaveTeste = chaveTeste;
    process.env.FBC_KEY = chaveTeste;
  }

  encrypt(texto) {
    return Criptografia.encrypt(texto);
  }

  decrypt(token) {
    return Criptografia.decrypt(token);
  }

  prefixo() {
    return 'FBC';
  }

  decompor(tokenDecodificado) {
    const buf = toBuffer(tokenDecodificado);
    const tamIv = this.tamanhoIv();
    return {
      integridade: buf.subarray(0, 32),
      ciphertext: buf.subarray(32, buf.length - tamIv),
      iv: buf.subarray(buf.length - tamIv),
    };
  }

  recompor(campos) {
    return Buffer.concat([campos.integridade, campos.ciphertext, campos.iv]);
  }

  gerarKeystreamBruto(key, iv, proposito, tamanho) {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    const ivBuf = toBuffer(iv);
    return Criptografia._internal.gerarKeystream(keyBuf, ivBuf, proposito, tamanho);
  }

  checksumBruto(dados, key) {
    const dadosBuf = toBuffer(dados);
    const keyBuf = toBuffer(key);
    return Criptografia._internal.checksum(dadosBuf, keyBuf);
  }

  chaveDeTeste() {
    return this._chaveTeste;
  }

  tamanhoIv() {
    return 16;
  }

  /** Ajuda os ataques a decodificar/codificar o base64url do token. */
  base64urlDecode(data) {
    return Criptografia.base64urlDecode(data);
  }

  base64urlEncode(data) {
    return Criptografia.base64urlEncode(data);
  }
}

module.exports = CriptografiaAlvo;

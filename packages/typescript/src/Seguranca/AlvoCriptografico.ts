/** Campos que compõem um token (já decodificado do base64url). */
export type CamposToken = {
  integridade: Buffer;
  ciphertext: Buffer;
  iv: Buffer;
};

/**
 * Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.
 *
 * Os métodos "obrigatórios" (encrypt/decrypt) bastam pros ataques de alto nível
 * (ida-e-volta, adulteração, colisão de IV, bytes fixos entre tokens).
 *
 * `gerarKeystreamBruto` e `checksumBruto` expõem as camadas internas para os
 * ataques de baixo nível (avalanche, distribuição, cobertura de dependência,
 * fold estrutural).
 */
export interface AlvoCriptografico {
  encrypt(texto: string | Buffer): string;

  decrypt(token: string): string;

  /** Prefixo esperado no início de um token válido (ex: "FBC"). */
  prefixo(): string;

  /** Decompõe um token (sem prefixo e já base64url-decodificado) nos campos. */
  decompor(tokenDecodificado: Buffer): CamposToken;

  /** Recompõe um token a partir dos campos (inverso de decompor()). */
  recompor(campos: CamposToken): Buffer;

  /**
   * Gera N bytes de keystream bruto a partir de key+iv+propósito.
   * Um alvo que não exponha essa camada deve lançar SkipAtaqueException.
   */
  gerarKeystreamBruto(
    key: Buffer | string,
    iv: Buffer | string,
    proposito: string,
    tamanho: number,
  ): Buffer;

  /** Chama o checksum() interno diretamente. */
  checksumBruto(dados: Buffer | string, key: Buffer | string): Buffer;

  /** Uma chave válida pra usar nos testes. */
  chaveDeTeste(): string;

  /** Tamanho do IV em bytes. */
  tamanhoIv(): number;

  base64urlEncode(data: Buffer): string;

  base64urlDecode(data: string): Buffer;
}

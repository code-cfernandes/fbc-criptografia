package fbc.Seguranca;

/**
 * Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.
 *
 * Os métodos "obrigatórios" (encrypt/decrypt) bastam pros ataques de alto nível.
 * {@code gerarKeystreamBruto} e {@code checksumBruto} expõem as camadas internas
 * para os ataques de baixo nível.
 */
public interface AlvoCriptografico {
    String encrypt(String texto);

    String encrypt(byte[] texto);

    String decrypt(String token);

    /** Prefixo esperado no início de um token válido (ex: "FBC"). */
    String prefixo();

    /** Decompõe um token (sem prefixo e já base64url-decodificado) nos campos. */
    CamposToken decompor(byte[] tokenDecodificado);

    /** Recompõe um token a partir dos campos (inverso de decompor()). */
    byte[] recompor(CamposToken campos);

    /** Gera N bytes de keystream bruto a partir de key+iv+propósito. */
    byte[] gerarKeystreamBruto(byte[] key, byte[] iv, String proposito, int tamanho);

    /** Chama o checksum() interno diretamente. */
    byte[] checksumBruto(byte[] dados, byte[] key);

    /** Uma chave válida pra usar nos testes. */
    String chaveDeTeste();

    /** Tamanho do IV em bytes. */
    int tamanhoIv();

    String base64urlEncode(byte[] data);

    byte[] base64urlDecode(String data);
}

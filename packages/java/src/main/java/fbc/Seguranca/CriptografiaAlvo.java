package fbc.Seguranca;

import fbc.Core.Criptografia;
import java.util.Arrays;

/**
 * Liga a suíte de ataques à classe Criptografia real, expondo as camadas
 * internas de keystream e checksum.
 */
public class CriptografiaAlvo implements AlvoCriptografico {
    public static final String CHAVE_PADRAO = "pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf";

    private final String chaveTeste;

    public CriptografiaAlvo() {
        this(CHAVE_PADRAO);
    }

    public CriptografiaAlvo(String chaveTeste) {
        this.chaveTeste = chaveTeste;
        Criptografia.definirChave(chaveTeste);
    }

    @Override
    public String encrypt(String texto) {
        return Criptografia.encrypt(texto);
    }

    @Override
    public String encrypt(byte[] texto) {
        return Criptografia.encrypt(texto);
    }

    @Override
    public String decrypt(String token) {
        return Criptografia.decrypt(token);
    }

    @Override
    public String prefixo() {
        return "FBC";
    }

    @Override
    public CamposToken decompor(byte[] tokenDecodificado) {
        int tamIv = tamanhoIv();
        return new CamposToken(
                Arrays.copyOfRange(tokenDecodificado, 0, 32),
                Arrays.copyOfRange(tokenDecodificado, 32, tokenDecodificado.length - tamIv),
                Arrays.copyOfRange(tokenDecodificado, tokenDecodificado.length - tamIv, tokenDecodificado.length));
    }

    @Override
    public byte[] recompor(CamposToken campos) {
        return Criptografia.concat(Criptografia.concat(campos.integridade, campos.ciphertext), campos.iv);
    }

    @Override
    public byte[] gerarKeystreamBruto(byte[] key, byte[] iv, String proposito, int tamanho) {
        return Criptografia.gerarKeystream(key, iv, proposito, tamanho);
    }

    @Override
    public byte[] checksumBruto(byte[] dados, byte[] key) {
        return Criptografia.checksum(dados, key);
    }

    @Override
    public String chaveDeTeste() {
        return this.chaveTeste;
    }

    @Override
    public int tamanhoIv() {
        return 16;
    }

    @Override
    public String base64urlEncode(byte[] data) {
        return Criptografia.base64urlEncode(data);
    }

    @Override
    public byte[] base64urlDecode(String data) {
        return Criptografia.base64urlDecode(data);
    }
}

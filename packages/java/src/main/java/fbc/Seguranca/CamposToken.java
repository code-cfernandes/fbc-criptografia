package fbc.Seguranca;

/** Campos que compõem um token (já decodificado do base64url). */
public class CamposToken {
    public byte[] integridade;
    public byte[] ciphertext;
    public byte[] iv;

    public CamposToken(byte[] integridade, byte[] ciphertext, byte[] iv) {
        this.integridade = integridade;
        this.ciphertext = ciphertext;
        this.iv = iv;
    }
}

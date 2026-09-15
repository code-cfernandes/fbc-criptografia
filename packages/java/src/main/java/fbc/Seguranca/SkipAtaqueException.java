package fbc.Seguranca;

/** Lançada quando o alvo não suporta os recursos que um ataque precisa. */
public class SkipAtaqueException extends RuntimeException {
    public SkipAtaqueException(String message) {
        super(message);
    }
}

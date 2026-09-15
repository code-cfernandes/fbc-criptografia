package fbc;

import fbc.Seguranca.CriptografiaAlvo;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * Runner de fuzzing cruzado da implementação Java.
 *
 * Lê casos no formato {@code chave|iv|proposito|plaintext} (hex) e escreve uma
 * linha {@code indice|keystream|mac} por caso, para comparação byte a byte com
 * as outras linguagens do monorepo.
 */
public final class FuzzCruzado {
    private FuzzCruzado() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("uso: FuzzCruzado <casos.txt> <saida.txt>");
            System.exit(2);
        }

        Path entrada = Path.of(args[0]);
        Path saida = Path.of(args[1]);

        CriptografiaAlvo alvo = new CriptografiaAlvo();
        HexFormat hex = HexFormat.of();

        try (BufferedReader leitor = Files.newBufferedReader(entrada, StandardCharsets.UTF_8);
                BufferedWriter escritor = Files.newBufferedWriter(saida, StandardCharsets.UTF_8)) {
            String linha;
            int indice = 0;
            while ((linha = leitor.readLine()) != null) {
                if (linha.isEmpty()) {
                    continue;
                }

                String[] partes = linha.split("\\|", -1);
                if (partes.length != 4) {
                    throw new IllegalArgumentException("Caso " + indice + " malformado: " + linha);
                }

                byte[] chave = hex.parseHex(partes[0]);
                byte[] iv = hex.parseHex(partes[1]);
                String proposito = partes[2];
                byte[] plaintext = hex.parseHex(partes[3]);

                byte[] keystream = alvo.gerarKeystreamBruto(chave, iv, proposito, plaintext.length);
                byte[] mac = alvo.checksumBruto(plaintext, chave);

                escritor.write(indice + "|" + hex.formatHex(keystream) + "|" + hex.formatHex(mac));
                escritor.newLine();
                indice++;
            }
        }
    }
}

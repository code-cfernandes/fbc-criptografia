#!/usr/bin/env python3
"""Runner de fuzzing cruzado: gera keystreams e checksums brutos a partir de
fuzz/casos.txt para comparação com as demais implementações.

uso: python3 bin/fuzz_cruzado.py <entrada> <saida>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.Seguranca.CriptografiaAlvo import CriptografiaAlvo


def main() -> int:
    caminho_entrada = sys.argv[1]
    caminho_saida = sys.argv[2]

    alvo = CriptografiaAlvo()

    with open(caminho_entrada, encoding="utf-8") as arquivo:
        linhas = [linha.strip() for linha in arquivo]
    linhas = [linha for linha in linhas if linha]

    saida = []

    for indice, linha in enumerate(linhas):
        chave_hex, iv_hex, proposito, plaintext_hex = linha.split("|")

        chave = bytes.fromhex(chave_hex)
        iv = bytes.fromhex(iv_hex)
        plaintext = bytes.fromhex(plaintext_hex)

        ks = alvo.gerar_keystream_bruto(chave, iv, proposito, len(plaintext))
        mac = alvo.checksum_bruto(plaintext, chave)

        saida.append(f"{indice}|{ks.hex()}|{mac.hex()}")

    with open(caminho_saida, "w", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(saida) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())

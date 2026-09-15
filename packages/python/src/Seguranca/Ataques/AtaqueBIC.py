"""BIC (Bit Independence Criterion): pares de bits de saída não devem estar
correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV
e registra quais bits de saída mudaram; depois mede a correlação (phi) entre
cada par de bits de saída. Pares muito correlacionados indicam difusão
acoplada (um bit "carrega" informação sobre outro).
"""

import math

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes, random_int


class AtaqueBIC:
    def __init__(self, tamanho_bloco: int = 32, amostras: int = 300, limite: float = 0.35):
        self.tamanho_bloco = tamanho_bloco
        self.amostras = amostras
        self.limite = limite

    def nome(self) -> str:
        return "BIC (Bit Independence Criterion)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste().encode()
        total_bits = self.tamanho_bloco * 8
        tamanho_iv = alvo.tamanho_iv()

        amostras_flips = []
        for _ in range(self.amostras):
            iv1 = random_bytes(tamanho_iv)
            iv2 = bytearray(iv1)
            pos = random_int(0, tamanho_iv - 1)
            iv2[pos] ^= 1 << random_int(0, 7)

            ks1 = alvo.gerar_keystream_bruto(chave, iv1, "enc", self.tamanho_bloco)
            ks2 = alvo.gerar_keystream_bruto(chave, bytes(iv2), "enc", self.tamanho_bloco)

            flips = [0] * total_bits
            for j in range(total_bits):
                b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1
                b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1
                flips[j] = 1 if b1 != b2 else 0
            amostras_flips.append(flips)

        pior_phi = 0.0
        pior_par = (-1, -1)
        n = self.amostras

        for a in range(total_bits):
            for b in range(a + 1, total_bits):
                n11 = n10 = n01 = n00 = 0
                for s in range(n):
                    fa = amostras_flips[s][a]
                    fb = amostras_flips[s][b]
                    if fa == 1 and fb == 1:
                        n11 += 1
                    elif fa == 1 and fb == 0:
                        n10 += 1
                    elif fa == 0 and fb == 1:
                        n01 += 1
                    else:
                        n00 += 1
                den = math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
                phi = (n11 * n00 - n10 * n01) / den if den > 0 else 0.0
                if abs(phi) > abs(pior_phi):
                    pior_phi = phi
                    pior_par = (a, b)

        vulneravel = abs(pior_phi) > self.limite

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"maior |phi|={abs(pior_phi):.3f} entre bits de saída "
            f"[{pior_par[0]}, {pior_par[1]}] (limite {self.limite}); {n} amostras",
            {"pior_phi": pior_phi, "par": pior_par},
        )

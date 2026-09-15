"""SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueSAC:
    def __init__(self, tamanho_bloco: int = 32, amostras: int = 40, tolerancia: float = 0.05):
        self.tamanho_bloco = tamanho_bloco
        self.amostras = amostras
        self.tolerancia = tolerancia

    def nome(self) -> str:
        return "SAC (Strict Avalanche Criterion)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste().encode()
        total_bits = self.tamanho_bloco * 8
        flips = [0] * total_bits
        tamanho_iv = alvo.tamanho_iv()
        total = 0

        for pos in range(tamanho_iv):
            for bit in range(8):
                for _ in range(self.amostras):
                    iv1 = random_bytes(tamanho_iv)
                    iv2 = bytearray(iv1)
                    iv2[pos] ^= 1 << bit

                    ks1 = alvo.gerar_keystream_bruto(chave, iv1, "enc", self.tamanho_bloco)
                    ks2 = alvo.gerar_keystream_bruto(chave, bytes(iv2), "enc", self.tamanho_bloco)

                    for j in range(total_bits):
                        b1 = (ks1[j >> 3] >> (7 - (j & 7))) & 1
                        b2 = (ks2[j >> 3] >> (7 - (j & 7))) & 1
                        if b1 != b2:
                            flips[j] += 1
                    total += 1

        pior = -1
        pior_desvio = 0.0
        pior_p = 0.5
        for j in range(total_bits):
            p = flips[j] / total
            desvio = abs(p - 0.5)
            if desvio > pior_desvio:
                pior_desvio = desvio
                pior = j
                pior_p = p

        vulneravel = pior_desvio > self.tolerancia
        detalhes = (
            f"pior bit de saída={pior}: p={pior_p * 100:.2f}% "
            f"(esperado 50%, tolerância ±{self.tolerancia * 100:.1f}%); "
            f"{total} amostras por bit de entrada"
        )

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            detalhes,
            {"pior": pior, "pior_p": pior_p, "desvio": pior_desvio},
        )

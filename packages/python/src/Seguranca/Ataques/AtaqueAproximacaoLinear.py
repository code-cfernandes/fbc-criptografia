"""Aproximação linear (criptoanálise de Matsui): procura por correlação entre
bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
aproximação linear com viés relevante; bias alto é uma pista explorável.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueAproximacaoLinear:
    def __init__(self, amostras: int = 200, tamanho_bloco: int = 32, limite_bias: float = 0.3):
        self.amostras = amostras
        self.tamanho_bloco = tamanho_bloco
        self.limite_bias = limite_bias

    def nome(self) -> str:
        return "Aproximação linear (viés de Walsh)"

    def executar(self, alvo) -> ResultadoAtaque:
        tam_iv = alvo.tamanho_iv()
        bits_entrada = tam_iv * 8
        bits_saida = self.tamanho_bloco * 8

        entradas = []
        saidas = []

        for _ in range(self.amostras):
            chave = random_bytes(len(alvo.chave_de_teste().encode()))
            iv = random_bytes(tam_iv)
            ks = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho_bloco)

            in_bits = [(iv[j >> 3] >> (7 - (j & 7))) & 1 for j in range(bits_entrada)]
            out_bits = [(ks[j >> 3] >> (7 - (j & 7))) & 1 for j in range(bits_saida)]
            entradas.append(in_bits)
            saidas.append(out_bits)

        maior_bias = 0.0
        par = (-1, -1)
        for i in range(bits_entrada):
            for j in range(bits_saida):
                iguais = sum(1 for s in range(self.amostras) if entradas[s][i] == saidas[s][j])
                bias = abs(iguais / self.amostras - 0.5)
                if bias > maior_bias:
                    maior_bias = bias
                    par = (i, j)

        vulneravel = maior_bias > self.limite_bias

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"maior viés |p-0.5|={maior_bias:.4f} na aproximação "
            f"IV[bit {par[0]}] -> saída[bit {par[1]}] (limite {self.limite_bias}); "
            f"{self.amostras} amostras",
            {"maior_bias": maior_bias, "par": par},
        )

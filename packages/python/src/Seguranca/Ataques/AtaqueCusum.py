"""Somas cumulativas (cusum), teste do NIST SP800-22.

Converte os bits em passos +1/-1 e observa o maior desvio da caminhada
aleatória. Um viés pequeno que o monobit quase não vê faz o desvio
acumulado crescer. Para uma sequência aleatória, max|S|/sqrt(n) fica
tipicamente abaixo de 3.
"""

from math import sqrt

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueCusum:
    def __init__(self, tamanho: int = 8192, limite_z: float = 4.0):
        self.tamanho = tamanho
        self.limite_z = limite_z

    def nome(self) -> str:
        return "Somas cumulativas (cusum)"

    def executar(self, alvo) -> ResultadoAtaque:
        ks = alvo.gerar_keystream_bruto(alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho)
        if ks is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        soma = 0
        max_abs = 0
        for i in range(len(ks)):
            byte = ks[i]
            for b in range(7, -1, -1):
                soma += 1 if ((byte >> b) & 1) == 1 else -1
                max_abs = max(max_abs, abs(soma))
        n = len(ks) * 8
        z = max_abs / sqrt(n)
        vulneravel = z > self.limite_z

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            f"max|S|={max_abs} sobre {n} bits, max|S|/sqrt(n)={z:.2f} (limite={self.limite_z:.1f})",
            {"max_abs": max_abs, "z": z},
        )

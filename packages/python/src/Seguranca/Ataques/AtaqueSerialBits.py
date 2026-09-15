"""Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
"""

import math

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueSerialBits:
    def __init__(self, tamanho: int = 4096, ordens=None):
        self.tamanho = tamanho
        self.ordens = [2, 3, 4] if ordens is None else ordens

    def nome(self) -> str:
        return "Teste serial (padrões de bits sobrepostos)"

    def executar(self, alvo) -> ResultadoAtaque:
        ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho
        )
        if ks is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        bits = self._para_bits(ks)
        n = len(bits)

        problemas = []
        dados = {}

        for m in self.ordens:
            total = 1 << m
            contagem = [0] * total
            janelas = n - m + 1

            for i in range(janelas):
                v = 0
                for j in range(m):
                    v = (v << 1) | bits[i + j]
                contagem[v] += 1

            esperado = janelas / total
            chi2 = 0.0
            for c in contagem:
                chi2 += ((c - esperado) ** 2) / esperado
            dof = total - 1
            # Wilson-Hilferty: aproximação normal bem mais precisa para dof
            # pequeno (o z "ingênuo" dá ~5% de falso positivo em dof=3).
            z = ((chi2 / dof) ** (1 / 3) - (1 - 2 / (9 * dof))) / math.sqrt(2 / (9 * dof))
            dados[f"m{m}"] = {"chi2": chi2, "z": z}

            if z > 6.0:
                problemas.append(f"m={m} chi2={chi2:.1f} (z={z:.1f})")

        if problemas:
            return ResultadoAtaque(
                self.nome(), True, "media", "; ".join(problemas), dados
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            "Padrões sobrepostos de 2/3/4 bits com frequência uniforme",
            dados,
        )

    def _para_bits(self, dados: bytes) -> list:
        bits = []
        for i in range(len(dados)):
            byte = dados[i]
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        return bits

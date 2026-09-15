"""O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
"""

from math import sqrt

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueDistribuicaoPorPosicao:
    def __init__(self, amostras_de_blocos: int = 2000, tamanho_bloco: int = 32):
        self.amostras_de_blocos = amostras_de_blocos
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Distribuição de bytes por posição do bloco"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        primeiro = alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        contagens = []
        for _ in range(self.tamanho_bloco):
            contagens.append([0] * 256)

        for _ in range(self.amostras_de_blocos):
            ks = alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco)
            for p in range(self.tamanho_bloco):
                contagens[p][ks[p]] += 1

        esperado = self.amostras_de_blocos / 256
        problemas = []
        pior = 0.0

        for p, c in enumerate(contagens):
            chi2 = 0.0
            for v in c:
                chi2 += ((v - esperado) ** 2) / esperado
            pior = max(pior, chi2)
            z = (chi2 - 255) / sqrt(510)
            if z > 4.0:
                problemas.append(f"posição {p} chi2={chi2:.1f}")

        if problemas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "media",
                "; ".join(problemas),
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todas as {self.tamanho_bloco} posições uniformes (pior chi2={pior:.1f}, esperado ~255)",
        )

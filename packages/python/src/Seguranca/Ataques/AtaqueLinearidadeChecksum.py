"""Procura linearidade no checksum, que seria fatal para um MAC:
 1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
 2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
    cada a; se repetir muito, existe um diferencial de alta probabilidade
    que ajuda a forjar MACs.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueLinearidadeChecksum:
    def __init__(
        self,
        amostras_linearidade: int = 5000,
        amostras_diferencial: int = 500,
        tamanho_entrada: int = 32,
    ):
        self.amostras_linearidade = amostras_linearidade
        self.amostras_diferencial = amostras_diferencial
        self.tamanho_entrada = tamanho_entrada

    def nome(self) -> str:
        return "Linearidade e diferenciais do checksum"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_mac = "M" * 32
        primeiro = alvo.checksum_bruto("teste", chave_mac)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe checksum_bruto.")

        relacoes_lineares = 0
        for _ in range(self.amostras_linearidade):
            a = random_bytes(self.tamanho_entrada)
            b = random_bytes(self.tamanho_entrada)
            lhs = self._xor_bytes(
                alvo.checksum_bruto(a, chave_mac),
                alvo.checksum_bruto(b, chave_mac),
            )
            rhs = alvo.checksum_bruto(self._xor_bytes(a, b), chave_mac)
            if lhs == rhs:
                relacoes_lineares += 1

        max_repeticoes_diferencial = 0
        for _ in range(5):
            delta = random_bytes(self.tamanho_entrada)
            vistos = {}
            for _ in range(self.amostras_diferencial):
                a = random_bytes(self.tamanho_entrada)
                dif = self._xor_bytes(
                    alvo.checksum_bruto(self._xor_bytes(a, delta), chave_mac),
                    alvo.checksum_bruto(a, chave_mac),
                )
                vistos[dif] = vistos.get(dif, 0) + 1
            max_repeticoes_diferencial = max(
                max_repeticoes_diferencial, max(vistos.values())
            )

        vulneravel = relacoes_lineares > 0 or max_repeticoes_diferencial > 1

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            f"{relacoes_lineares}/{self.amostras_linearidade} relações "
            f"lineares; maior repetição de diferencial="
            f"{max_repeticoes_diferencial} (esperado 1)",
            {
                "relacoes_lineares": relacoes_lineares,
                "max_repeticoes_diferencial": max_repeticoes_diferencial,
            },
        )

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

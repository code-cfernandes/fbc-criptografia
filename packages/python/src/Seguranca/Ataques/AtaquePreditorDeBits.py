"""Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
primeira metade do keystream e mede a taxa de acerto na segunda metade.
Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
Qualquer coisa acima disso indica que os bits carregam dependência
explorável - o embrião de um ataque de predição de estado.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaquePreditorDeBits:
    def __init__(self, tamanho: int = 16384, contexto: int = 8, limite_taxa: float = 0.55):
        self.tamanho = tamanho
        self.contexto = contexto
        self.limite_taxa = limite_taxa

    def nome(self) -> str:
        return "Previsibilidade de bits (preditor por contexto)"

    def executar(self, alvo) -> ResultadoAtaque:
        ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho
        )
        if ks is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        bits = self._para_bits(ks)
        n = len(bits)
        k = self.contexto
        total = 1 << k
        metade = n // 2

        uns = [0] * total
        cont = [0] * total
        for i in range(k, metade):
            ctx = self._contexto(bits, i, k)
            uns[ctx] += bits[i]
            cont[ctx] += 1

        acertos = 0
        testes = 0
        for i in range(metade, n):
            ctx = self._contexto(bits, i, k)
            if cont[ctx] == 0:
                continue
            predicao = 1 if uns[ctx] * 2 > cont[ctx] else 0
            if predicao == bits[i]:
                acertos += 1
            testes += 1

        taxa = acertos / testes if testes > 0 else 0.5
        vulneravel = taxa > self.limite_taxa

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"taxa de acerto={taxa * 100:.2f}% com contexto de {k} bits "
            f"(esperado ~50%, limite={self.limite_taxa * 100:.0f}%) sobre {testes} testes",
            {"taxa": taxa, "testes": testes},
        )

    def _contexto(self, bits: list, i: int, k: int) -> int:
        ctx = 0
        for j in range(i - k, i):
            ctx = (ctx << 1) | bits[j]
        return ctx

    def _para_bits(self, bytes_: bytes) -> list:
        bits = []
        for i in range(len(bytes_)):
            byte = bytes_[i]
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        return bits

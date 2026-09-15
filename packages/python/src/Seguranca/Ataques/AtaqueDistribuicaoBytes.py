"""Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
de byte saem com mais frequência que outros - sinal de fraqueza estatística
na função de mistura.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueDistribuicaoBytes:
    def __init__(self, amostras_de_blocos: int = 500, tamanho_bloco: int = 32):
        self.amostras_de_blocos = amostras_de_blocos
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Distribuição de bytes (qui-quadrado)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        primeiro = alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        contagem = [0] * 256
        total = 0
        for _ in range(self.amostras_de_blocos):
            ks = alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco)
            for j in range(len(ks)):
                contagem[ks[j]] += 1
                total += 1

        esperado = total / 256
        qui2 = 0.0
        for c in contagem:
            qui2 += ((c - esperado) ** 2) / esperado

        # Com 255 graus de liberdade, valores acima de ~330 já são
        # estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
        vulneravel = qui2 > 330

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            f"qui-quadrado={qui2:.1f} sobre {total} bytes "
            f"(255 graus de liberdade; >330 é suspeito)",
            {"qui2": qui2},
        )

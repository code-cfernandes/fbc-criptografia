"""Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
gerado (efeito avalanche). Números muito abaixo disso indicam difusão
fraca - foi o que achamos quando o número de rodadas de mistura era
baixo demais numa das versões anteriores.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import bits_diferentes, random_bytes, random_int


class AtaqueAvalanche:
    def __init__(
        self,
        amostras: int = 3000,
        tamanho_bloco: int = 32,
        limite_media: float = 0.45,
        limite_pior_caso: float = 0.30,
    ):
        self.amostras = amostras
        self.tamanho_bloco = tamanho_bloco
        self.limite_media = limite_media
        self.limite_pior_caso = limite_pior_caso

    def nome(self) -> str:
        return "Efeito avalanche"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste().encode()
        tamanho_iv = alvo.tamanho_iv()

        primeiro = alvo.gerar_keystream_bruto(chave, random_bytes(tamanho_iv), "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        valores = []
        for t in range(self.amostras):
            iv1 = random_bytes(tamanho_iv)
            iv2 = bytearray(iv1)
            pos = random_int(0, tamanho_iv - 1)
            iv2[pos] ^= 1 << random_int(0, 7)

            ks1 = alvo.gerar_keystream_bruto(chave, iv1, "enc", self.tamanho_bloco)
            ks2 = alvo.gerar_keystream_bruto(chave, bytes(iv2), "enc", self.tamanho_bloco)

            valores.append(bits_diferentes(ks1, ks2) / (self.tamanho_bloco * 8))

        valores = sorted(valores)
        n = len(valores)
        media = sum(valores) / n
        pior_caso = valores[0]

        vulneravel = media < self.limite_media or pior_caso < self.limite_pior_caso

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            (
                f"média={media * 100:.1f}%, pior caso={pior_caso * 100:.1f}%, "
                f"percentil 1%={valores[int(n * 0.01)] * 100:.1f}% "
                f"(limites: média>={self.limite_media * 100:.0f}%, pior>={self.limite_pior_caso * 100:.0f}%)"
            ),
            {"media": media, "pior_caso": pior_caso},
        )

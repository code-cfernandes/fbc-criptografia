"""O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
Números baixos indicam que parte da chave tem pouca influência - o que
reduziria o espaço de busca de um atacante.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import bits_diferentes, random_bytes, random_int


class AtaqueAvalancheChave:
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
        return "Efeito avalanche da chave"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_base = alvo.chave_de_teste()
        len_chave = len(chave_base)
        iv = random_bytes(alvo.tamanho_iv())

        primeiro = alvo.gerar_keystream_bruto(chave_base.encode(), iv, "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        valores = []
        for t in range(self.amostras):
            chave = bytearray(chave_base.encode())
            pos = random_int(0, len_chave - 1)
            chave[pos] ^= 1 << random_int(0, 7)

            ks1 = alvo.gerar_keystream_bruto(chave_base.encode(), iv, "enc", self.tamanho_bloco)
            ks2 = alvo.gerar_keystream_bruto(bytes(chave), iv, "enc", self.tamanho_bloco)

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
                f"média={media * 100:.1f}%, pior caso={pior_caso * 100:.1f}% "
                f"(limites: média>={self.limite_media * 100:.0f}%, pior>={self.limite_pior_caso * 100:.0f}%)"
            ),
            {"media": media, "pior_caso": pior_caso},
        )

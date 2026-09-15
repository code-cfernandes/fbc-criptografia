from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueComplexidadeLinear:
    """
    Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
    reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
    complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
    um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
    seria atacável resolvendo um sistema linear em vez de força bruta.
    """

    def __init__(
        self,
        bits_por_amostra: int = 1024,
        amostras: int = 5,
        limite_relativo: float = 0.40,
    ):
        self.bits_por_amostra = bits_por_amostra
        self.amostras = amostras
        self.limite_relativo = limite_relativo

    def nome(self) -> str:
        return "Complexidade linear (Berlekamp-Massey)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        primeiro = alvo.gerar_keystream_bruto(
            chave, random_bytes(alvo.tamanho_iv()), "enc", 64
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        relativos = []
        pior = 1.0
        for _ in range(self.amostras):
            bytes_ = alvo.gerar_keystream_bruto(
                chave,
                random_bytes(alvo.tamanho_iv()),
                "enc",
                self.bits_por_amostra // 8,
            )
            bits = self.para_bits(bytes_, self.bits_por_amostra)
            relativo = self.berlekamp_massey(bits) / self.bits_por_amostra
            relativos.append(relativo)
            pior = min(pior, relativo)

        media = sum(relativos) / len(relativos)
        vulneravel = pior < self.limite_relativo

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            f"complexidade linear relativa: média={media * 100:.1f}%, "
            f"pior={pior * 100:.1f}% de {self.bits_por_amostra} bits "
            f"(esperado ~50%; limite>={self.limite_relativo * 100:.0f}%)",
            {"media": media, "pior": pior},
        )

    def para_bits(self, bytes_: bytes, limite: int) -> list:
        bits = []
        for i in range(len(bytes_)):
            if len(bits) >= limite:
                break
            byte = bytes_[i]
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        return bits[:limite]

    def berlekamp_massey(self, s: list) -> int:
        """Algoritmo de Berlekamp-Massey sobre GF(2)."""
        n = len(s)
        c = [0] * n
        c[0] = 1
        b = [0] * n
        b[0] = 1
        l = 0
        m = -1

        for i in range(n):
            d = s[i]
            for j in range(1, l + 1):
                d ^= c[j] & s[i - j]

            if d == 1:
                t = c[:]
                shift = i - m
                j = 0
                while j + shift < n:
                    c[j + shift] ^= b[j]
                    j += 1
                if l <= i // 2:
                    l = i + 1 - l
                    m = i
                    b = t

        return l

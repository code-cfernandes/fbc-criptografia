"""Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
0xFF, complemento) não devem gerar keystreams correlacionados. Um key
schedule fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem
estrutura (distância de Hamming baixa).
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import bits_diferentes, random_bytes


class AtaqueChaveRelacionada:
    def __init__(
        self,
        tamanho_bloco: int = 32,
        iv_por_delta: int = 3,
        limite_media: float = 0.45,
        limite_pior: float = 0.3,
    ):
        self.tamanho_bloco = tamanho_bloco
        self.iv_por_delta = iv_por_delta
        self.limite_media = limite_media
        self.limite_pior = limite_pior

    def nome(self) -> str:
        return "Chave relacionada (related-key)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_base = alvo.chave_de_teste().encode()
        tamanho = len(chave_base)

        deltas = []
        for i in range(tamanho):
            d = bytearray(tamanho)
            d[i] = 0x01
            deltas.append(bytes(d))
        for i in range(tamanho):
            d = bytearray(tamanho)
            d[i] = 0xFF
            deltas.append(bytes(d))
        deltas.append(bytes(b ^ 0xFF for b in chave_base))

        valores = []
        total_bits = self.tamanho_bloco * 8

        for delta in deltas:
            chave_relacionada = bytearray(chave_base)
            for i in range(tamanho):
                chave_relacionada[i] ^= delta[i]
            for _ in range(self.iv_por_delta):
                iv = random_bytes(alvo.tamanho_iv())
                ks1 = alvo.gerar_keystream_bruto(chave_base, iv, "enc", self.tamanho_bloco)
                ks2 = alvo.gerar_keystream_bruto(bytes(chave_relacionada), iv, "enc", self.tamanho_bloco)
                valores.append(bits_diferentes(ks1, ks2) / total_bits)

        media = sum(valores) / len(valores)
        pior = min(valores)
        vulneravel = media < self.limite_media or pior < self.limite_pior

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"média={media * 100:.1f}%, pior={pior * 100:.1f}% "
            f"em {len(valores)} pares (limites: média>={self.limite_media * 100:.0f}%, "
            f"pior>={self.limite_pior * 100:.0f}%)",
            {"media": media, "pior": pior},
        )

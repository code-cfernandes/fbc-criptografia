"""Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
`keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
byte e também coincidência direta do keystream.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


def rotacionar(buf: bytes, k: int) -> bytes:
    n = len(buf)
    return bytes(buf[(i + k) % n] for i in range(n))


class AtaqueRotacional:
    def __init__(self, tamanho: int = 64):
        self.tamanho = tamanho

    def nome(self) -> str:
        return "Rotacional/slide (simetria por rotação)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste().encode()
        iv = random_bytes(alvo.tamanho_iv())
        ks1 = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho)

        coincidencias = []
        for k in range(1, len(chave)):
            ks2 = alvo.gerar_keystream_bruto(
                rotacionar(chave, k),
                rotacionar(iv, k),
                "enc",
                self.tamanho,
            )

            if ks2 == ks1:
                coincidencias.append(f"rotação {k}: keystream idêntico")
                continue
            # metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
            alvo_rot = rotacionar(ks1[:32], k)
            if ks2[:32] == alvo_rot:
                coincidencias.append(f"rotação {k}: keystream rotacionado")

        vulneravel = len(coincidencias) > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            (
                f"Simetria rotacional encontrada: {'; '.join(coincidencias[:5])}"
                if vulneravel
                else f"Nenhuma das {len(chave) - 1} rotações de byte reproduziu o keystream"
            ),
            {"coincidencias": coincidencias},
        )

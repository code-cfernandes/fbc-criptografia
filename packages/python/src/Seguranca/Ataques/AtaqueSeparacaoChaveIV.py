"""Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
resto do gerador não reintroduzir key/iv separadamente, vale exatamente:

    keystream(key, iv) == keystream(key ^ d, iv ^ d)

para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
propriedade estrutural relevante: significa que key e iv não entram de
forma independente na cifra, o que enfraquece o modelo de segurança (o IV
deveria contribuir com entropia própria, não só deslocar a chave por XOR).
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueSeparacaoChaveIV:
    def __init__(self, tentativas: int = 50, tamanho_bloco: int = 32):
        self.tentativas = tentativas
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Separação chave/IV (invariância a key XOR iv)"

    def executar(self, alvo) -> ResultadoAtaque:
        tam_chave = len(alvo.chave_de_teste())
        tam_iv = alvo.tamanho_iv()

        primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), random_bytes(tam_iv), "enc", self.tamanho_bloco
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        confirmacoes = 0
        for t in range(self.tentativas):
            chave = random_bytes(tam_chave)
            iv = random_bytes(tam_iv)
            d = random_bytes(tam_iv)

            chave2 = bytearray(tam_chave)
            for p in range(tam_chave):
                chave2[p] = chave[p] ^ d[p % tam_iv]
            iv2 = bytearray(tam_iv)
            for p in range(tam_iv):
                iv2[p] = iv[p] ^ d[p]

            ks1 = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho_bloco)
            ks2 = alvo.gerar_keystream_bruto(bytes(chave2), bytes(iv2), "enc", self.tamanho_bloco)

            if ks1 == ks2:
                confirmacoes += 1

        invariante = confirmacoes == self.tentativas

        return ResultadoAtaque(
            self.nome(),
            invariante,
            "media" if invariante else "info",
            f"Confirmado em {self.tentativas}/{self.tentativas}: "
            "keystream(key,iv) == keystream(key^d, iv^d). "
            "O IV só desloca a chave por XOR antes da difusão - não injeta entropia "
            "independente no key schedule."
            if invariante
            else f"Invariância não se confirmou ({confirmacoes}/{self.tentativas}); "
            "key e iv entram de forma independente.",
            {"confirmacoes": confirmacoes, "tentativas": self.tentativas},
        )

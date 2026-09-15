import os

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueChaveErrada:
    """
    Garante que um token só decifra com a chave correta: com qualquer outra
    chave de 32 bytes, decrypt() tem que lançar. Verifica também que a chave
    errada não "quase funciona" (ex: aceitar às vezes por MAC fraco).

    Cuidado: CriptografiaAlvo escreve a chave no ambiente do processo; a chave
    original é restaurada no final pra não afetar os outros ataques.
    """

    def __init__(self, tentativas: int = 30):
        self.tentativas = tentativas

    def nome(self) -> str:
        return "Rejeição de chave incorreta"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException(
                "Precisa de CriptografiaAlvo para trocar a chave."
            )

        chave_original = alvo.chave_de_teste()

        tokens = []
        for i in range(self.tentativas):
            tokens.append(alvo.encrypt(f"MENSAGEM_SECRETA_{i}"))

        aceitos = []
        try:
            for i, token in enumerate(tokens):
                CriptografiaAlvo(random_bytes(16).hex())
                try:
                    r = alvo.decrypt(token)
                    aceitos.append(f"tentativa {i} aceitou (retornou {r})")
                except Exception:
                    # esperado
                    pass
        finally:
            os.environ["FBC_KEY"] = chave_original

        if aceitos:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"{len(aceitos)} de {self.tentativas} tokens foram aceitos com a chave errada",
                {"exemplos": aceitos[:5]},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Nenhum dos {self.tentativas} tokens foi aceito com chave incorreta",
        )

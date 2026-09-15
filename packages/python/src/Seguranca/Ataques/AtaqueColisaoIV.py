from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueColisaoIV:
    """
    Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
    garantias de confidencialidade (keystream reusado = "two-time pad").
    Gera muitos tokens do MESMO texto e verifica se os IVs nunca colidem.
    """

    def __init__(self, geracoes: int = 5000):
        self.geracoes = geracoes

    def nome(self) -> str:
        return "Colisão de IV"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_decode do alvo.")

        vistos = set()
        colisoes = 0

        for _ in range(self.geracoes):
            token = alvo.encrypt("MESMO_TEXTO_SEMPRE")
            decodificado = alvo.base64url_decode(token[len(alvo.prefixo()) :])
            iv = alvo.decompor(decodificado)["iv"]
            chave_iv = iv.hex()
            if chave_iv in vistos:
                colisoes += 1
            vistos.add(chave_iv)

        if colisoes > 0:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"{colisoes} colisão(ões) de IV em {self.geracoes} gerações",
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"0 colisões em {self.geracoes} gerações",
        )

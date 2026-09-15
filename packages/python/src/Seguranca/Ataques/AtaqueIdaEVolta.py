"""Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
de decrypt precisa devolver o texto original, em qualquer tamanho.
Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
segurança mais sério por trás (foi assim em quase todas as rodadas
anteriores dessa conversa).
"""

from ..ResultadoAtaque import ResultadoAtaque


class AtaqueIdaEVolta:
    def __init__(self, tamanho_maximo: int = 130):
        self.tamanho_maximo = tamanho_maximo

    def nome(self) -> str:
        return "Ida-e-volta (round trip)"

    def executar(self, alvo) -> ResultadoAtaque:
        falhas = []
        for length in range(self.tamanho_maximo + 1):
            texto = "Q" * length
            try:
                token = alvo.encrypt(texto)
                decifrado = alvo.decrypt(token)
                if decifrado != texto:
                    falhas.append(length)
            except Exception as e:
                falhas.append(f"{length} (erro: {e})")

        if falhas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                "Falhou em "
                + str(len(falhas))
                + " tamanho(s): "
                + ", ".join(str(f) for f in falhas[:10]),
                {"falhas": falhas},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todos os {self.tamanho_maximo + 1} tamanhos "
            f"(0 a {self.tamanho_maximo}) OK",
        )

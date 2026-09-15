"""A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
bytes válida deve funcionar. Uma validação frouxa aqui vira uma chave mais
curta (e mais fraca) na prática.
"""

import os

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueValidacaoChave:
    def __init__(self, tamanhos=None):
        self.tamanhos = [0, 1, 16, 31, 33, 64] if tamanhos is None else tamanhos

    def nome(self) -> str:
        return "Validação do tamanho da chave"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de CriptografiaAlvo para trocar a chave.")

        chave_original = alvo.chave_de_teste()
        aceitas_indevidamente = []
        valida_rejeitada = False

        try:
            for length in self.tamanhos:
                CriptografiaAlvo("K" * length)
                try:
                    alvo.encrypt("x")
                    aceitas_indevidamente.append(length)
                except Exception:
                    # esperado
                    pass

            CriptografiaAlvo("K" * 32)
            try:
                alvo.encrypt("x")
            except Exception:
                valida_rejeitada = True
        finally:
            os.environ["FBC_KEY"] = chave_original

        vulneravel = bool(aceitas_indevidamente) or valida_rejeitada

        detalhes = []
        if aceitas_indevidamente:
            detalhes.append(
                "chaves de tamanho inválido aceitas: "
                + ", ".join(str(x) for x in aceitas_indevidamente)
            )
        if valida_rejeitada:
            detalhes.append("chave válida de 32 bytes foi rejeitada")

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            "; ".join(detalhes)
            if vulneravel
            else "Tamanhos inválidos rejeitados e chave de 32 bytes aceita",
        )

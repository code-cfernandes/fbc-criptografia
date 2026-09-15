"""Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
sincronização de bloco, repetição de keystream em blocos distantes ou
perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
gera tokens diferentes.

Adaptação Python: a API do alvo recebe `str`; geramos os bytes aleatórios e
os representamos via latin-1 (bijeção byte<->code point) para depois
comparar os BYTES originais com o resultado reencodado.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueMensagemLonga:
    def __init__(self, tamanhos=None):
        self.tamanhos = [1000, 10000, 100000] if tamanhos is None else tamanhos

    def nome(self) -> str:
        return "Mensagens longas (multi-bloco)"

    def executar(self, alvo) -> ResultadoAtaque:
        falhas = []

        for t in self.tamanhos:
            texto_bytes = random_bytes(t)
            texto = texto_bytes.decode("latin-1")
            try:
                token = alvo.encrypt(texto)
                if alvo.decrypt(token).encode("latin-1") != texto_bytes:
                    falhas.append(f"{t} bytes (conteúdo diferente)")
            except Exception as e:
                falhas.append(f"{t} bytes (erro: {e})")

        texto = "A" * 1000
        t1 = alvo.encrypt(texto)
        t2 = alvo.encrypt(texto)
        if t1 == t2:
            falhas.append("tokens idênticos para o mesmo texto (IV não varia)")

        if falhas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                "Falha em: " + "; ".join(falhas),
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            "Ida-e-volta OK em "
            + ", ".join(str(t) for t in self.tamanhos)
            + " bytes; mesmo texto gera tokens distintos",
        )

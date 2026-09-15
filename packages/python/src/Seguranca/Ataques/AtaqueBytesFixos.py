"""As primeiras versões dessa cifra tinham um header fixo (43 bytes idênticos
sempre) ou um marcador constante (o '$' na posição 64). Esse ataque gera
vários tokens de textos diferentes e procura qualquer posição de byte que
NUNCA muda - isso é uma âncora que um atacante pode usar pra recuperar a
chave (como fizemos na primeira rodada dessa conversa).
"""

from ..ResultadoAtaque import ResultadoAtaque


class AtaqueBytesFixos:
    def __init__(self, amostras: int = 30):
        self.amostras = amostras

    def nome(self) -> str:
        return "Bytes fixos entre tokens"

    def executar(self, alvo) -> ResultadoAtaque:
        tokens = []
        for i in range(self.amostras):
            texto = "TEXTO_VARIADO_" + str(i) + chr(65 + (i % 26)) * (i % 10)
            tokens.append(alvo.encrypt(texto)[len(alvo.prefixo()):])

        decodificados = [alvo.base64url_decode(t) for t in tokens]
        tamanho_minimo = min(len(d) for d in decodificados)

        posicoes_fixas = []
        for i in range(tamanho_minimo):
            valores = [d[i] for d in decodificados]
            if len(set(valores)) == 1:
                posicoes_fixas.append(i)

        if posicoes_fixas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "alta",
                (
                    f"{len(posicoes_fixas)} posição(ões) de byte fixas em {self.amostras} tokens: "
                    + ", ".join(str(p) for p in posicoes_fixas[:10])
                ),
                {"posicoes": posicoes_fixas},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"0 de {tamanho_minimo} posições fixas em {self.amostras} tokens",
        )

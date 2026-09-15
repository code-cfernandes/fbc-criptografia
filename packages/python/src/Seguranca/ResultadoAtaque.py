"""Resultado de rodar um ataque contra um alvo.

`vulneravel = True` significa que o ataque ACHOU um problema (a cifra falhou).
`vulneravel = False` significa que a cifra resistiu a esse ataque específico.
"""


class ResultadoAtaque:
    def __init__(self, nome_ataque, vulneravel, severidade, detalhes, dados=None):
        self.nome_ataque = nome_ataque
        self.vulneravel = vulneravel
        self.severidade = severidade
        self.detalhes = detalhes
        self.dados = dados

    def linha_resumo(self) -> str:
        if self.severidade == "pulado":
            status = "PULADO"
        elif self.severidade == "demonstracao":
            status = "DEMONSTRAÇÃO"
        else:
            status = "❌ VULNERÁVEL" if self.vulneravel else "✅ resistiu"

        return f"[{status}] {self.nome_ataque} ({self.severidade}): {self.detalhes}"

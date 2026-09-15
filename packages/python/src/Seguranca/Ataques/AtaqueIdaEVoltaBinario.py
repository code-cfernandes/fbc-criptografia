"""O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
truncation) só aparecem com bytes arbitrários.

Adaptação Python: a API do alvo recebe/devolve `str` (codificado em UTF-8
internamente), então mapeamos cada byte para um caractere via latin-1 -
uma bijeção byte<->code point, que preserva NUL e todos os 256 valores -
e reencodamos o resultado para comparar os BYTES originais.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueIdaEVoltaBinario:
    def __init__(self, tamanho_maximo: int = 256):
        self.tamanho_maximo = tamanho_maximo

    def nome(self) -> str:
        return "Ida-e-volta com dados binários (inclui NUL)"

    def executar(self, alvo) -> ResultadoAtaque:
        falhas = []

        for length in range(self.tamanho_maximo + 1):
            texto_bytes = b"" if length == 0 else random_bytes(length)
            texto = texto_bytes.decode("latin-1")
            try:
                decifrado = alvo.decrypt(alvo.encrypt(texto))
                if decifrado.encode("latin-1") != texto_bytes:
                    falhas.append(length)
            except Exception as e:
                falhas.append(f"{length} (erro: {e})")

        todos_bytes = bytes(range(256))
        todos = todos_bytes.decode("latin-1")
        if alvo.decrypt(alvo.encrypt(todos)).encode("latin-1") != todos_bytes:
            falhas.append("todos os 256 valores de byte")

        if falhas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                "Falhou em "
                + str(len(falhas))
                + " caso(s): "
                + ", ".join(str(f) for f in falhas[:10]),
                {"falhas": falhas},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todos os tamanhos 0..{self.tamanho_maximo} e os 256 valores "
            "de byte preservados",
        )

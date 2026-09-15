"""O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
keystream aleatório deve ter todos esses indicadores perto de zero/50%.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import contar_bits1, random_bytes


class AtaqueAutocorrelacao:
    def __init__(self, tamanho: int = 8192, tamanho_bloco: int = 32):
        self.tamanho = tamanho
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Autocorrelação e periodicidade do keystream"

    def executar(self, alvo) -> ResultadoAtaque:
        ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().encode(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho
        )
        if ks is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        serial = self._correlacao(ks, 1)

        suspeitos = {}
        for lag in [2, 4, 8, 16, 32, 64, 128, 256]:
            c = self._correlacao(ks, lag)
            if abs(c) > 0.10:
                suspeitos[lag] = c

        blocos = [ks[i:i + self.tamanho_bloco] for i in range(0, len(ks), self.tamanho_bloco)]
        blocos_repetidos = len(blocos) - len(set(blocos))

        uns = 0
        for i in range(len(ks)):
            uns += contar_bits1(ks[i])
        fracao_uns = uns / (len(ks) * 8)

        problemas = []
        if abs(serial) > 0.10:
            problemas.append(f"correlação serial={serial:.3f}")
        if suspeitos:
            problemas.append("autocorrelação em lag(s) " + ", ".join(str(k) for k in suspeitos.keys()))
        if blocos_repetidos > 0:
            problemas.append(f"{blocos_repetidos} bloco(s) de {self.tamanho_bloco} bytes repetido(s)")
        if fracao_uns < 0.45 or fracao_uns > 0.55:
            problemas.append(f"balanço de bits={fracao_uns * 100:.1f}% de 1s")

        if problemas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "media",
                "; ".join(problemas),
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            (
                f"serial={serial:.3f}, nenhum lag com correlação >10%, "
                f"0 blocos repetidos em {len(blocos)}, {fracao_uns * 100:.1f}% de bits 1"
            ),
        )

    def _correlacao(self, s: bytes, lag: int) -> float:
        n = len(s)
        if n <= lag:
            return 0.0

        media = sum(s) / n
        num = 0.0
        den = 0.0
        for i in range(n):
            den += (s[i] - media) ** 2
        for i in range(n - lag):
            num += (s[i] - media) * (s[i + lag] - media)

        return num / den if den > 0 else 0.0

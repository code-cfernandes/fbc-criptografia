"""Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
posições de saída é exatamente o tipo de estrutura que o antigo bug da
"metade igual" produzia - e que a autocorrelação temporal pode não pegar.
"""

from math import sqrt

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueCorrelacaoPosicoes:
    def __init__(self, amostras: int = 3000, tamanho_bloco: int = 32, limite_correlacao: float = 0.15):
        self.amostras = amostras
        self.tamanho_bloco = tamanho_bloco
        self.limite_correlacao = limite_correlacao

    def nome(self) -> str:
        return "Correlação entre posições do bloco"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        primeiro = alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        blocos = []
        for _ in range(self.amostras):
            blocos.append(alvo.gerar_keystream_bruto(chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco))

        suspeitos = []
        pior = 0.0

        for a in range(self.tamanho_bloco):
            for b in range(a + 1, self.tamanho_bloco):
                corr = self.pearson(blocos, a, b)
                if abs(corr) > abs(pior):
                    pior = corr
                if abs(corr) > self.limite_correlacao:
                    suspeitos.append(f"posições {a}-{b} (r={corr:.3f})")

        if suspeitos:
            return ResultadoAtaque(
                self.nome(),
                True,
                "alta",
                f"{len(suspeitos)} par(es) correlacionado(s): " + "; ".join(suspeitos[:10]),
                {"suspeitos": suspeitos},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Nenhum par de posições correlacionado acima de {self.limite_correlacao:.2f} "
            f"(pior |r|={abs(pior):.3f})",
        )

    def pearson(self, blocos: list, a: int, b: int) -> float:
        n = len(blocos)
        ma = 0.0
        mb = 0.0
        for d in blocos:
            ma += d[a]
            mb += d[b]
        ma /= n
        mb /= n

        num = 0.0
        da = 0.0
        db = 0.0
        for d in blocos:
            xa = d[a] - ma
            xb = d[b] - mb
            num += xa * xb
            da += xa * xa
            db += xb * xb

        return num / sqrt(da * db) if da > 0 and db > 0 else 0.0

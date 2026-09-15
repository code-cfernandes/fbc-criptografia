"""Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
previsibilidade local: para uma sequência aleatória, a chance de repetir um
bloco de m bits deve cair suavemente conforme m cresce. Estruturas
periódicas/recorrentes produzem ApEn anômala.

O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
um valor esperado teórico. Comparamos o keystream com um CONTROLE de
random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
estatisticamente indistinguíveis.
"""

from math import log, sqrt

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueEntropiaAproximada:
    def __init__(
        self,
        tamanho: int = 4096,
        m: int = 8,
        controles: int = 12,
        amostras_keystream: int = 3,
        limite_z: float = 5.0,
    ):
        self.tamanho = tamanho
        self.m = m
        self.controles = controles
        self.amostras_keystream = amostras_keystream
        self.limite_z = limite_z

    def nome(self) -> str:
        return "Entropia aproximada (ApEn vs controle aleatório)"

    def executar(self, alvo) -> ResultadoAtaque:
        primeiro = alvo.gerar_keystream_bruto(alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", 64)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        chi_controle = []
        for _ in range(self.controles):
            chi_controle.append(self.estatistico(random_bytes(self.tamanho)))
        media_controle = sum(chi_controle) / len(chi_controle)
        variancia = 0.0
        for v in chi_controle:
            variancia += (v - media_controle) ** 2
        desvio_controle = sqrt(variancia / max(1, len(chi_controle) - 1))

        chi_keystream = []
        for _ in range(self.amostras_keystream):
            ks = alvo.gerar_keystream_bruto(alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho)
            chi_keystream.append(self.estatistico(ks))
        media_keystream = sum(chi_keystream) / len(chi_keystream)

        z = (media_keystream - media_controle) / desvio_controle if desvio_controle > 0 else 0.0
        vulneravel = abs(z) > self.limite_z

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            f"chi2 keystream={media_keystream:.1f}, controle={media_controle:.1f} "
            f"(sd={desvio_controle:.1f}), z={z:.2f} (limite={self.limite_z:.1f})",
            {"chi_keystream": media_keystream, "chi_controle": media_controle, "z": z},
        )

    def estatistico(self, bytes_: bytes) -> float:
        """chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1)."""
        bits = self.para_bits(bytes_)
        n = len(bits)
        apen = self.phi(bits, self.m, n) - self.phi(bits, self.m + 1, n)
        return 2 * n * (log(2) - apen)

    def phi(self, bits: list, m: int, n: int) -> float:
        total = 1 << m
        contagem = [0] * total
        janelas = n - m + 1

        for i in range(janelas):
            v = 0
            for j in range(m):
                v = (v << 1) | bits[i + j]
            contagem[v] += 1

        soma = 0.0
        for c in contagem:
            if c > 0:
                p = c / janelas
                soma += p * log(p)

        return soma

    def para_bits(self, bytes_: bytes) -> list:
        bits = []
        for i in range(len(bytes_)):
            byte = bytes_[i]
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        return bits

"""Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
(qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
de cifra sólida deve parecer ruído mesmo com plaintext variado.
"""

import math

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueCiphertextEstatistico:
    def __init__(self, amostras: int = 200, tamanho_texto: int = 64, z_limite: float = 4):
        self.amostras = amostras
        self.tamanho_texto = tamanho_texto
        self.z_limite = z_limite

    def nome(self) -> str:
        return "Estatística do ciphertext (chi²/runs/autocorrelação)"

    def executar(self, alvo) -> ResultadoAtaque:
        contagem = [0] * 256
        bytes_ = []

        for _ in range(self.amostras):
            texto = random_bytes(self.tamanho_texto).decode("latin-1")
            token = alvo.encrypt(texto)
            campos = alvo.decompor(alvo.base64url_decode(token[len(alvo.prefixo()) :]))
            for b in campos["ciphertext"]:
                contagem[b] += 1
                bytes_.append(b)

        total = len(bytes_)
        esperado = total / 256
        chi2 = 0.0
        for b in range(256):
            d = contagem[b] - esperado
            chi2 += (d * d) / esperado

        # runs test nos bits do ciphertext
        uns = 0
        bits = []
        for b in bytes_:
            for k in range(7, -1, -1):
                bit = (b >> k) & 1
                bits.append(bit)
                uns += bit
        n = len(bits)
        pi = uns / n
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i - 1]:
                runs += 1
        esperado_runs = 2 * n * pi * (1 - pi)
        desvio_runs = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        z_runs = abs(runs - esperado_runs) / desvio_runs if desvio_runs > 0 else 0.0

        # autocorrelação lag-1
        media = sum(bytes_) / total
        num = 0.0
        den = 0.0
        for i in range(total):
            den += (bytes_[i] - media) ** 2
        for i in range(total - 1):
            num += (bytes_[i] - media) * (bytes_[i + 1] - media)
        autocorr = num / den if den > 0 else 0.0

        problemas = []
        if chi2 > 330:
            problemas.append(f"qui-quadrado={chi2:.1f} (>330 suspeito)")
        if z_runs > self.z_limite:
            problemas.append(f"runs z={z_runs:.2f}")
        if abs(autocorr) > 0.1:
            problemas.append(f"autocorrelação={autocorr:.3f}")

        vulneravel = len(problemas) > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            (
                "; ".join(problemas)
                if vulneravel
                else f"qui-quadrado={chi2:.1f} sobre {total} bytes, runs z={z_runs:.2f}, "
                f"autocorrelação={autocorr:.3f} - todos dentro do esperado"
            ),
            {"chi2": chi2, "runs_z": z_runs, "autocorrelacao": autocorr},
        )

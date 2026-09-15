"""Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
global (monobit), frequência por posição de bit, teste de runs e frequência
por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.

Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
pra não depender de funções numéricas especiais.
"""

import math

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueBateriaEstatistica:
    def __init__(self, tamanho: int = 16384, z_limite: float = 4.0):
        self.tamanho = tamanho
        self.z_limite = z_limite

    def nome(self) -> str:
        return "Bateria estatística de bits (monobit/runs/blocos)"

    def executar(self, alvo) -> ResultadoAtaque:
        ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().encode(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho
        )
        if ks is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        bits = self._para_bits(ks)
        n = len(bits)
        problemas = []
        dados = {}

        # 1) Monobit: soma +1/-1
        soma = 0
        for b in bits:
            soma += 1 if b == 1 else -1
        z_monobit = abs(soma) / math.sqrt(n)
        dados["monobit_z"] = z_monobit
        if z_monobit > self.z_limite:
            problemas.append(f"monobit z={z_monobit:.2f}")

        # 2) Frequência por posição de bit
        uns_por_pos = [0] * 8
        conta_por_pos = [0] * 8
        for c in ks:
            byte = c
            for b in range(8):
                if ((byte >> b) & 1) == 1:
                    uns_por_pos[b] += 1
                conta_por_pos[b] += 1
        pos_viesadas = {}
        for b in range(8):
            uns = uns_por_pos[b]
            frac = uns / conta_por_pos[b]
            z = abs(frac - 0.5) / (0.5 / math.sqrt(conta_por_pos[b]))
            if z > self.z_limite:
                pos_viesadas[b] = frac
        dados["bit_posicao_viesadas"] = pos_viesadas
        if pos_viesadas:
            problemas.append("viés por posição de bit: " + ", ".join(str(k) for k in pos_viesadas.keys()))

        # 3) Runs test
        pi = sum(bits) / n
        if abs(pi - 0.5) < 2 / math.sqrt(n):
            runs = 1
            for i in range(1, n):
                if bits[i] != bits[i - 1]:
                    runs += 1
            esperado = 2 * n * pi * (1 - pi)
            desvio = 2 * math.sqrt(2 * n) * pi * (1 - pi)
            z_runs = abs(runs - esperado) / desvio
            dados["runs_z"] = z_runs
            if z_runs > self.z_limite:
                problemas.append(f"runs z={z_runs:.2f}")

        # 4) Frequência por bloco (M = 128 bits)
        m = 128
        num_blocos = n // m
        if num_blocos > 0:
            chi = 0.0
            for i in range(num_blocos):
                uns = 0
                for j in range(m):
                    uns += bits[i * m + j]
                chi += ((uns / m) - 0.5) ** 2
            chi *= 4 * m
            z_blocos = (chi - num_blocos) / math.sqrt(2 * num_blocos)
            dados["blocos_chi2"] = chi
            dados["blocos_z"] = z_blocos
            if z_blocos > self.z_limite:
                problemas.append(f"frequência por bloco chi2={chi:.1f}")

        if problemas:
            return ResultadoAtaque(self.nome(), True, "media", "; ".join(problemas), dados)

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            (
                f"monobit z={z_monobit:.2f}, runs z={dados.get('runs_z', 0.0):.2f}, "
                f"blocos chi2={dados.get('blocos_chi2', 0.0):.1f} - todos abaixo do limite z={self.z_limite:.0f}"
            ),
            dados,
        )

    def _para_bits(self, bytes_: bytes) -> list:
        bits = []
        for i in range(len(bytes_)):
            byte = bytes_[i]
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        return bits

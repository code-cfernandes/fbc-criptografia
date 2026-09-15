"""Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.

Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
a saída como função do byte variado fica "quase bijetiva" e a soma tende a
zero MUITO mais que o acaso - um distinguisher clássico.

Como uma única (chave, IV) tem variância alta, acumula várias tentativas
para estimar o viés de forma estável (comparado a p=1/256).
"""

import math

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueIntegral:
    def __init__(
        self,
        tamanho_bloco: int = 32,
        posicoes_iv: int = 8,
        posicoes_chave: int = 8,
        tentativas: int = 16,
        limite_z: float = 5.0,
    ):
        self.tamanho_bloco = tamanho_bloco
        self.posicoes_iv = posicoes_iv
        self.posicoes_chave = posicoes_chave
        self.tentativas = tentativas
        self.limite_z = limite_z

    def nome(self) -> str:
        return "Integral (soma balanceada variando 1 byte de IV/chave)"

    def executar(self, alvo) -> ResultadoAtaque:
        tam_iv = alvo.tamanho_iv()
        tam_chave = len(alvo.chave_de_teste().encode())

        primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), random_bytes(tam_iv), "enc", self.tamanho_bloco
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        distinguidores = []
        zeros_total = 0
        bytes_total = 0

        for _ in range(self.tentativas):
            chave = random_bytes(tam_chave)
            iv_base = random_bytes(tam_iv)

            for pos in range(min(self.posicoes_iv, tam_iv)):
                xor, zeros = self._somar_variando(alvo, chave, iv_base, "iv", pos)
                zeros_total += zeros
                bytes_total += self.tamanho_bloco
                if xor == b"\x00" * self.tamanho_bloco:
                    distinguidores.append(f"iv[{pos}]")

            for pos in range(min(self.posicoes_chave, tam_chave)):
                xor, zeros = self._somar_variando(alvo, chave, iv_base, "key", pos)
                zeros_total += zeros
                bytes_total += self.tamanho_bloco
                if xor == b"\x00" * self.tamanho_bloco:
                    distinguidores.append(f"key[{pos}]")

        p = 1 / 256
        esperado = bytes_total * p
        desvio = math.sqrt(bytes_total * p * (1 - p))
        z = (zeros_total - esperado) / desvio if desvio > 0 else 0.0

        vulneravel = bool(distinguidores) or z > self.limite_z

        if distinguidores:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                "Soma balanceada (XOR zero) encontrada variando: "
                + ", ".join(distinguidores[:10]),
                {"distinguidores": distinguidores},
            )

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            f"bytes de saída zerados={zeros_total} "
            f"(esperado ~{esperado:.1f}, z={z:.2f}) em {bytes_total} amostras; "
            f"limite z={self.limite_z:.1f}",
            {"zeros": zeros_total, "esperado": esperado, "z": z},
        )

    def _somar_variando(self, alvo, chave, iv_base, campo, pos):
        """XOR de 256 keystreams e quantos bytes deram zero."""
        xor = bytearray(b"\x00" * self.tamanho_bloco)
        for v in range(256):
            k = bytearray(chave)
            iv = bytearray(iv_base)
            if campo == "iv":
                iv[pos] = v
            else:
                k[pos] = v
            ks = alvo.gerar_keystream_bruto(
                bytes(k), bytes(iv), "enc", self.tamanho_bloco
            )
            for i in range(self.tamanho_bloco):
                xor[i] ^= ks[i]
        return bytes(xor), xor.count(0)

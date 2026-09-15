"""Esse é o ataque que pegou o bug mais sério que encontramos: quando a
distância de mistura era exatamente metade do bloco, TODOS os IVs
aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
"""

import json

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueFoldEstrutural:
    def __init__(self, amostras: int = 5000, tamanho_bloco: int = 32):
        self.amostras = amostras
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Fold estrutural (metades/quartos/oitavos repetidos)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        primeiro = alvo.gerar_keystream_bruto(
            chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        divisores = [
            d
            for d in [2, 4, 8, 16]
            if self.tamanho_bloco % d == 0 and self.tamanho_bloco // d >= 1
        ]
        ocorrencias = {d: 0 for d in divisores}

        # Limite de "ruído esperado" por acaso: pra fatias de tam bytes,
        # a chance de colisão por acaso é ~1/256^tam por par comparado -
        # desprezível para tam >= 2, então qualquer contagem > 0 já é
        # suspeita o bastante pra investigar (ajustamos a margem pra
        # fatias de 1-2 bytes, onde colisão por acaso é mais provável).
        for _ in range(self.amostras):
            ks = alvo.gerar_keystream_bruto(
                chave, random_bytes(alvo.tamanho_iv()), "enc", self.tamanho_bloco
            )
            for divisor in divisores:
                tam_fatia = self.tamanho_bloco // divisor
                primeira = ks[:tam_fatia]
                for j in range(1, divisor):
                    if ks[j * tam_fatia : (j + 1) * tam_fatia] == primeira:
                        ocorrencias[divisor] += 1
                        break

        def margem(divisor):
            if self.tamanho_bloco / divisor <= 2:
                return int(self.amostras * 0.01) + 3
            return 5

        problemas = {d: c for d, c in ocorrencias.items() if c > margem(d)}

        if problemas:
            detalhe = ", ".join(
                f"1/{d} do bloco repetido em {c}/{self.amostras}"
                for d, c in problemas.items()
            )
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                detalhe,
                {"ocorrencias": ocorrencias},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            "Nenhuma repetição estrutural acima do ruído esperado: "
            + json.dumps(ocorrencias),
        )

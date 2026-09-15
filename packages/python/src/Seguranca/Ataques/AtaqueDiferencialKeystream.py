"""Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
boa, essas diferenças são uniformes e únicas. Sinaliza:
 - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
 - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
   que é o insumo básico de um ataque diferencial.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes, random_int


class AtaqueDiferencialKeystream:
    def __init__(self, amostras: int = 2000, tamanho_bloco: int = 32):
        self.amostras = amostras
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Diferencial do keystream (delta fixo no IV)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = random_bytes(len(alvo.chave_de_teste()))
        tamanho_iv = alvo.tamanho_iv()
        primeiro = alvo.gerar_keystream_bruto(chave, random_bytes(tamanho_iv), "enc", self.tamanho_bloco)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        delta = bytearray(b"\x00" * tamanho_iv)
        delta[random_int(0, tamanho_iv - 1)] = 1 << random_int(0, 7)

        total_bits = self.tamanho_bloco * 8
        sempre_zero = [True] * total_bits
        sempre_um = [True] * total_bits
        deltas = set()

        for _ in range(self.amostras):
            iv = random_bytes(tamanho_iv)
            iv2 = self.xor_bytes(iv, delta)

            ks1 = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho_bloco)
            ks2 = alvo.gerar_keystream_bruto(chave, iv2, "enc", self.tamanho_bloco)
            d = self.xor_bytes(ks1, ks2)
            deltas.add(d)

            for p in range(len(d)):
                byte = d[p]
                for b in range(8):
                    idx = p * 8 + b
                    if ((byte >> b) & 1) == 1:
                        sempre_zero[idx] = False
                    else:
                        sempre_um[idx] = False

        bits_fixos = 0
        for idx in range(total_bits):
            if sempre_zero[idx] or sempre_um[idx]:
                bits_fixos += 1
        colisoes = self.amostras - len(deltas)

        vulneravel = bits_fixos > 0 or colisoes > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"delta de 1 bit no IV: {bits_fixos} bit(s) de saída fixo(s), "
            f"{colisoes} diferencial(is) repetido(s) em {self.amostras} amostras",
            {"bits_fixos": bits_fixos, "colisoes": colisoes},
        )

    def xor_bytes(self, a, b) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

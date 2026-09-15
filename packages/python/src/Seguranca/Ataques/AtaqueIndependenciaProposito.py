"""A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
chave do MAC ('mac'). Se os dois streams não forem independentes, um
atacante que recupere o keystream de dados (ataque de texto conhecido)
pode derivar a chave do MAC e FORJAR tokens válidos.

O teste procura dois sintomas de acoplamento:
 1. a distância de Hamming média entre os streams deve ser ~50%;
 2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
    uma máscara fixa, o mac é 100% previsível a partir do enc.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import bits_diferentes, random_bytes


class AtaqueIndependenciaProposito:
    def __init__(self, amostras: int = 2000, tamanho: int = 32):
        self.amostras = amostras
        self.tamanho = tamanho

    def nome(self) -> str:
        return (
            "Independência entre keystreams de propósitos diferentes "
            "(enc x mac)"
        )

    def executar(self, alvo) -> ResultadoAtaque:
        primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), random_bytes(alvo.tamanho_iv()), "enc", self.tamanho
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        distancias = []
        mascaras = {}
        for _ in range(self.amostras):
            chave = random_bytes(len(alvo.chave_de_teste().encode()))
            iv = random_bytes(alvo.tamanho_iv())

            enc = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho)
            mac = alvo.gerar_keystream_bruto(chave, iv, "mac", self.tamanho)

            distancias.append(bits_diferentes(enc, mac) / (self.tamanho * 8))
            mascaras[self._xor_bytes(enc, mac)] = True

        media = sum(distancias) / len(distancias)
        mascaras_distintas = len(mascaras)

        vulneravel = (
            media < 0.40 or media > 0.60 or mascaras_distintas < self.amostras
        )

        detalhe = (
            f"Hamming médio enc x mac={media * 100:.1f}% (esperado ~50%); "
            f"{mascaras_distintas} máscara(s) XOR distinta(s) em "
            f"{self.amostras} amostras"
        )
        if mascaras_distintas < self.amostras:
            detalhe += " - MÁSCARA REPETIDA: mac previsível a partir de enc!"

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            detalhe,
            {"media": media, "mascaras_distintas": mascaras_distintas},
        )

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

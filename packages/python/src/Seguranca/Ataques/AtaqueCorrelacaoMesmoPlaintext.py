"""O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.

Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
venham do mesmo texto, se comportam como se fossem de textos diferentes
(distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).

Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
cifrar 500 textos diferentes.
"""

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import contar_bits1, random_int


class AtaqueCorrelacaoMesmoPlaintext:
    def __init__(self, amostras: int = 300, texto_fixo: str = "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR"):
        self.amostras = amostras
        self.texto_fixo = texto_fixo

    def nome(self) -> str:
        return "Correlação entre ciphertexts do mesmo plaintext"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_decode do alvo.")

        ciphertexts = []
        for _ in range(self.amostras):
            token = alvo.encrypt(self.texto_fixo)
            decodificado = alvo.base64url_decode(token[len(alvo.prefixo()):])
            ciphertexts.append(alvo.decompor(decodificado)["ciphertext"])

        # Compara pares aleatórios de ciphertexts (não todos contra todos,
        # pra manter o custo baixo) e mede a distância de Hamming média.
        comparacoes = min(500, int(self.amostras * (self.amostras - 1) / 2))
        distancias = []
        for _ in range(comparacoes):
            i = random_int(0, self.amostras - 1)
            j = random_int(0, self.amostras - 1)
            if i == j:
                continue
            distancias.append(self.distancia_hamming_relativa(ciphertexts[i], ciphertexts[j]))

        media = sum(distancias) / len(distancias)

        # Também confere que nenhum PAR de ciphertexts é idêntico (o que
        # indicaria reuso de IV+key, capturado de outro ângulo).
        duplicatas = len(ciphertexts) - len(set(ciphertexts))

        vulneravel = media < 0.40 or media > 0.60 or duplicatas > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            f"distância de Hamming média entre ciphertexts do mesmo texto: {media * 100:.1f}% "
            f"(esperado ~50%), {duplicatas} duplicata(s) exata(s) em {self.amostras} amostras",
            {"media": media, "duplicatas": duplicatas},
        )

    def distancia_hamming_relativa(self, a: bytes, b: bytes) -> float:
        tam = min(len(a), len(b))
        if tam == 0:
            return 0.5
        diff = 0
        for i in range(tam):
            diff += contar_bits1(a[i] ^ b[i])
        return diff / (tam * 8)

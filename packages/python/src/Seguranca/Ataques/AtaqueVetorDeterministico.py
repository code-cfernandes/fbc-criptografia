"""Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico -
chamar a função duas vezes com a mesma entrada tem que dar o mesmo
resultado, sempre. Se não der, alguma fonte de aleatoriedade (relógio,
random_bytes, uniqid, etc.) vazou pra dentro de uma função que deveria
ser pura - isso quebraria o decrypt() em produção de forma intermitente
e seria um pesadelo de debugar.

De brinde, esse ataque imprime o "vetor de referência" (Known Answer
Vector) pra esse par key/iv - guarde esse valor: se ele mudar entre
versões do código sem você ter mexido de propósito na lógica de mistura,
é sinal de uma regressão acidental.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueVetorDeterministico:
    def nome(self) -> str:
        return "Determinismo (vetor de referência key/iv fixos)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_fixa = "K" * len(alvo.chave_de_teste())  # chave fixa e conhecida
        iv_fixo = b"\x00" * alvo.tamanho_iv()  # IV fixo (só pra este teste)

        ks1 = alvo.gerar_keystream_bruto(chave_fixa, iv_fixo, "enc", 32)
        if ks1 is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")
        ks2 = alvo.gerar_keystream_bruto(chave_fixa, iv_fixo, "enc", 32)
        ks3 = alvo.gerar_keystream_bruto(chave_fixa, iv_fixo, "enc", 32)

        deterministico = (ks1 == ks2) and (ks2 == ks3)

        return ResultadoAtaque(
            self.nome(),
            not deterministico,
            "info" if deterministico else "critica",
            'Determinístico em 3 chamadas. Vetor de referência (key=64x"K", iv=zeros, prop=enc, 32 bytes): '
            + ks1.hex()
            if deterministico
            else "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: "
            + ks1.hex()
            + " / "
            + ks2.hex()
            + " / "
            + ks3.hex(),
            {"vetor_hex": ks1.hex()},
        )

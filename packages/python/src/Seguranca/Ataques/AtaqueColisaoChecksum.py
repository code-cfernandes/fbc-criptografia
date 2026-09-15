from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes


class AtaqueColisaoChecksum:
    """
    Procura colisões no checksum() via paradoxo do aniversário: gera muitas
    mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
    propósito aqui - testar resistência a colisão é uma propriedade do
    ALGORITMO, independente de a chave ser secreta ou não; é assim que se
    testa qualquer função de hash/MAC na prática).

    Testa dois níveis:
    1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
       aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
       tentativas pelo paradoxo do aniversário).
    2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
       estatisticamente com poucas dezenas de milhares de tentativas (o
       paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
       pra 50% de chance). Isso não quebra o MAC completo (que depende dos
       32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
       útil pra saber se a composição das rodadas está de fato preservando
       a força total, ou se há alguma correlação entre elas.
    """

    def __init__(self, amostras: int = 200000):
        self.amostras = amostras

    def nome(self) -> str:
        return "Colisão no checksum (paradoxo do aniversário)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_de_mac = b"M" * 32  # chave conhecida de propósito - ver docstring

        primeiro = alvo.checksum_bruto(b"teste", chave_de_mac)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe checksum_bruto.")

        vistos_completo = {}
        vistos_truncado = {}
        colisao_completa = None
        colisao_truncada = None

        for _ in range(self.amostras):
            mensagem = random_bytes(20)
            hash_ = alvo.checksum_bruto(mensagem, chave_de_mac)

            if colisao_completa is None:
                chave_hash = hash_.hex()
                if chave_hash in vistos_completo:
                    colisao_completa = [vistos_completo[chave_hash], mensagem]
                else:
                    vistos_completo[chave_hash] = mensagem

            if colisao_truncada is None:
                truncado = hash_[:4].hex()
                if truncado in vistos_truncado:
                    colisao_truncada = [vistos_truncado[truncado], mensagem]
                else:
                    vistos_truncado[truncado] = mensagem

            if colisao_completa is not None and colisao_truncada is not None:
                break

        # Colisão no checksum COMPLETO com essa amostra pequena seria uma
        # falha estrutural séria (a probabilidade por acaso é desprezível).
        if colisao_completa is not None:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"COLISÃO COMPLETA encontrada em {len(vistos_completo)} amostras - "
                "isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.",
                {
                    "msg1_hex": colisao_completa[0].hex(),
                    "msg2_hex": colisao_completa[1].hex(),
                },
            )

        # Colisão truncada (32 bits) é esperada estatisticamente - não é
        # "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
        # força que deveriam ter (nem mais, nem menos).
        info_truncada = (
            f"colisão de 32 bits encontrada em {len(vistos_truncado)} amostras "
            "(esperado pelo paradoxo do aniversário)"
            if colisao_truncada is not None
            else f"nenhuma colisão de 32 bits em {len(vistos_truncado)} amostras "
            "(um pouco abaixo do esperado, mas não conclusivo)"
        )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Nenhuma colisão completa em {self.amostras} amostras (esperado). "
            f"Nível truncado (32 bits): {info_truncada}.",
            {
                "amostras_completo": len(vistos_completo),
                "amostras_truncado": len(vistos_truncado),
            },
        )

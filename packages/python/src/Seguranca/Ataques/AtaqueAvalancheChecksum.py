"""O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
posição específica significa que aquele byte quase não influencia o MAC -
uma pista forte de que a mistura tem um "ponto cego" estrutural.

Varre TODAS as posições/bits da entrada (não amostra aleatória) para
apontar exatamente onde está o ponto fraco.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import bits_diferentes, random_bytes


class AtaqueAvalancheChecksum:
    def __init__(
        self,
        mensagens_por_combinacao: int = 10,
        tamanho_entrada: int = 32,
        limite_media: float = 0.40,
        limite_pior_caso: float = 0.40,
    ):
        self.mensagens_por_combinacao = mensagens_por_combinacao
        self.tamanho_entrada = tamanho_entrada
        self.limite_media = limite_media
        self.limite_pior_caso = limite_pior_caso

    def nome(self) -> str:
        return "Efeito avalanche do checksum/MAC"

    def executar(self, alvo) -> ResultadoAtaque:
        chave_mac = b"M" * 32

        primeiro = alvo.checksum_bruto(b"teste", chave_mac)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe checksum_bruto.")
        tamanho_saida = len(primeiro)

        soma_global = 0.0
        combinacoes = 0
        pior = {"posicao": -1, "bit": -1, "valor": 1.0}

        for pos in range(self.tamanho_entrada):
            for bit in range(8):
                soma = 0.0
                for m in range(self.mensagens_por_combinacao):
                    entrada = random_bytes(self.tamanho_entrada)
                    alterada = bytearray(entrada)
                    alterada[pos] ^= 1 << bit

                    h1 = alvo.checksum_bruto(entrada, chave_mac)
                    h2 = alvo.checksum_bruto(bytes(alterada), chave_mac)

                    soma += bits_diferentes(h1, h2) / (tamanho_saida * 8)
                media = soma / self.mensagens_por_combinacao

                soma_global += media
                combinacoes += 1
                if media < pior["valor"]:
                    pior = {"posicao": pos, "bit": bit, "valor": media}

        media_global = soma_global / combinacoes
        vulneravel = media_global < self.limite_media or pior["valor"] < self.limite_pior_caso

        if not vulneravel:
            severidade = "info"
        elif pior["valor"] < 0.30:
            severidade = "alta"
        else:
            severidade = "media"

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            severidade,
            (
                f"média global={media_global * 100:.1f}%; pior caso={pior['valor'] * 100:.1f}% "
                f"na entrada[posição={pior['posicao']}, bit={pior['bit']}] sobre {tamanho_saida} bytes de MAC "
                f"(limites: média>={self.limite_media * 100:.0f}%, pior>={self.limite_pior_caso * 100:.0f}%)"
            ),
            {"media_global": media_global, "pior": pior},
        )

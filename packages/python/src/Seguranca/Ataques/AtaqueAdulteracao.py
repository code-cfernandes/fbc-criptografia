"""O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
sucesso", a cifra não está autenticando o conteúdo - é a falha que
encontramos e corrigimos várias vezes ao longo dessa conversa.
"""

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import array_rand_key, random_int


class AtaqueAdulteracao:
    def __init__(self, tentativas: int = 500):
        self.tentativas = tentativas

    def nome(self) -> str:
        return "Adulteração de bits (integridade)"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_encode/decode do alvo.")

        aceitos_indevidamente = []

        for t in range(self.tentativas):
            texto = f"MSG_{t}" + "X" * random_int(0, 50)
            token = alvo.encrypt(texto)
            decodificado = alvo.base64url_decode(token[len(alvo.prefixo()):])
            campos = alvo.decompor(decodificado)

            nome_campo = array_rand_key(campos)
            valor = campos[nome_campo]
            if len(valor) == 0:
                continue
            pos = random_int(0, len(valor) - 1)
            valor = bytearray(valor)
            valor[pos] ^= 1 << random_int(0, 7)
            campos[nome_campo] = bytes(valor)

            token_adulterado = alvo.prefixo() + alvo.base64url_encode(alvo.recompor(campos))

            try:
                resultado = alvo.decrypt(token_adulterado)
                aceitos_indevidamente.append(
                    f"campo={nome_campo}, texto original={texto}, resultado aceito={resultado}"
                )
            except Exception:
                # esperado - a adulteração deveria ser rejeitada
                pass

        if aceitos_indevidamente:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"{len(aceitos_indevidamente)} de {self.tentativas} tokens adulterados foram ACEITOS",
                {"exemplos": aceitos_indevidamente[:5]},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todas as {self.tentativas} adulterações foram rejeitadas",
        )

"""Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
(força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
"""

from ..ResultadoAtaque import ResultadoAtaque


class AtaqueMac:
    def __init__(self, mensagem: str = "mensagem para o ataque de MAC"):
        self.mensagem = mensagem

    def nome(self) -> str:
        return "Força bruta e truncamento do MAC"

    def executar(self, alvo) -> ResultadoAtaque:
        token = alvo.encrypt(self.mensagem)
        decodificado = alvo.base64url_decode(token[len(alvo.prefixo()) :])
        campos = alvo.decompor(decodificado)

        def montar(integridade: bytes) -> str:
            return alvo.prefixo() + alvo.base64url_encode(
                alvo.recompor(
                    {
                        "integridade": integridade,
                        "ciphertext": campos["ciphertext"],
                        "iv": campos["iv"],
                    }
                )
            )

        aceitos = []

        # 1) integridade zerada
        try:
            alvo.decrypt(montar(bytes(len(campos["integridade"]))))
            aceitos.append("integridade zerada")
        except Exception:
            # esperado
            pass

        # 2) integridade truncada pela metade
        try:
            alvo.decrypt(montar(campos["integridade"][:16]))
            aceitos.append("integridade truncada (16 bytes)")
        except Exception:
            # esperado
            pass

        # 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
        # que reconstruiria o próprio token válido e não é uma forja)
        base = campos["integridade"]
        for v in range(256):
            if v == base[0]:
                continue
            tentativa = bytearray(base)
            tentativa[0] = v
            try:
                alvo.decrypt(montar(bytes(tentativa)))
                aceitos.append(f"byte 0 do MAC = {v}")
            except Exception:
                # esperado
                pass

        vulneravel = len(aceitos) > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            (
                f"{len(aceitos)} variante(s) de MAC aceitas: {'; '.join(aceitos[:5])}"
                if vulneravel
                else "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita"
            ),
            {"aceitos": aceitos},
        )

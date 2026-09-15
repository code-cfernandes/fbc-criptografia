"""Length extension / truncamento: a estrutura do token é
integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
Truncar, estender ou deslocar bytes não pode produzir um token aceito.
"""

from ..ResultadoAtaque import ResultadoAtaque


class AtaqueLengthExtension:
    def __init__(self, mensagem: str = "texto para o ataque de length extension"):
        self.mensagem = mensagem

    def nome(self) -> str:
        return "Length extension / truncamento de token"

    def executar(self, alvo) -> ResultadoAtaque:
        prefixo = alvo.prefixo()
        token = alvo.encrypt(self.mensagem)
        corpo = token[len(prefixo) :]
        meio = len(corpo) // 2

        variantes = {
            "append A": prefixo + corpo + "A",
            "append =": prefixo + corpo + "=",
            "truncar 1 char": prefixo + corpo[:-1],
            "truncar 2 chars": prefixo + corpo[:-2],
            "inserir ! no meio": prefixo + corpo[:meio] + "!" + corpo[meio:],
            "prefixo extra": prefixo + "A" + corpo,
        }

        # variantes que mexem nos campos decodificados
        try:
            decodificado = alvo.base64url_decode(corpo)
            campos = alvo.decompor(decodificado)

            ct_maior = campos["ciphertext"] + b"\x41"
            variantes["ciphertext +1 byte"] = prefixo + alvo.base64url_encode(
                alvo.recompor(
                    {
                        "integridade": campos["integridade"],
                        "ciphertext": ct_maior,
                        "iv": campos["iv"],
                    }
                )
            )

            ct_menor = campos["ciphertext"][: max(0, len(campos["ciphertext"]) - 1)]
            variantes["ciphertext -1 byte"] = prefixo + alvo.base64url_encode(
                alvo.recompor(
                    {
                        "integridade": campos["integridade"],
                        "ciphertext": ct_menor,
                        "iv": campos["iv"],
                    }
                )
            )

            iv_maior = campos["iv"] + b"\x42"
            variantes["iv +1 byte"] = prefixo + alvo.base64url_encode(
                alvo.recompor(
                    {
                        "integridade": campos["integridade"],
                        "ciphertext": campos["ciphertext"],
                        "iv": iv_maior,
                    }
                )
            )
        except Exception:
            # se a decodificação falhar, segue com as variantes textuais
            pass

        aceitas = []
        for nome_variante, v in variantes.items():
            if v == token:
                continue
            try:
                alvo.decrypt(v)
                aceitas.append(nome_variante)
            except Exception:
                # esperado
                pass

        vulneravel = len(aceitas) > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "critica" if vulneravel else "info",
            (
                f"{len(aceitas)} variante(s) aceita(s): {'; '.join(aceitas)}"
                if vulneravel
                else f"Todas as {len(variantes)} variantes de truncamento/extensão foram rejeitadas"
            ),
            {"aceitas": aceitas},
        )

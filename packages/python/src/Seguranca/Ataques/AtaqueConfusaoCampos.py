from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueConfusaoCampos:
    """
    O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
    ambíguo, um atacante pode reordenar/deslocar os campos e construir um
    token que sistemas diferentes interpretam de formas diferentes. Todos os
    rearranjos devem ser rejeitados pela integridade.
    """

    def nome(self) -> str:
        return "Confusão de campos do token (reordenação/deslocamento)"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException(
                "Precisa de base64url_encode/decode do alvo."
            )

        texto = "MENSAGEM_PARA_TESTE_DE_CAMPOS"
        token = alvo.encrypt(texto)
        prefixo = alvo.prefixo()
        campos = alvo.decompor(alvo.base64url_decode(token[len(prefixo) :]))

        integridade = campos["integridade"]
        ciphertext = campos["ciphertext"]
        iv = campos["iv"]

        variantes = {
            "iv no início": iv + integridade + ciphertext,
            "ciphertext antes da integridade": ciphertext + integridade + iv,
            "iv duplicado no fim": integridade + ciphertext + iv + iv,
            "integridade encurtada": integridade[1:] + ciphertext + iv,
            "byte extra no início": b"X" + integridade + ciphertext + iv,
            "byte extra entre integridade e ciphertext": integridade
            + b"X"
            + ciphertext
            + iv,
            "byte extra antes do iv": integridade + ciphertext + b"X" + iv,
            "iv rotacionado": integridade + ciphertext + iv[::-1],
            "iv e último byte do ciphertext trocados": integridade
            + ciphertext[:-1]
            + iv
            + ciphertext[-1:],
        }

        aceitas = []
        for nome, bruto in variantes.items():
            token_variante = prefixo + alvo.base64url_encode(bruto)
            try:
                r = alvo.decrypt(token_variante)
                aceitas.append(
                    f"{nome} -> aceito (retornou {len(r.encode('utf-8'))} bytes)"
                )
            except Exception:
                # esperado
                pass

        if aceitas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"{len(aceitas)} rearranjo(s) de campo foram aceitos",
                {"exemplos": aceitas},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todos os {len(variantes)} rearranjos de campo foram rejeitados",
        )

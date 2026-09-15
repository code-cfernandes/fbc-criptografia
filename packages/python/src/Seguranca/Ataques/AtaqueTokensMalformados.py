"""Robustez do parser de tokens: qualquer entrada que não seja um token
íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
é uma porta pra bugs de validação e "token smuggling".
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import random_bytes


class AtaqueTokensMalformados:
    def nome(self) -> str:
        return "Tokens malformados (fuzzing de entrada)"

    def executar(self, alvo) -> ResultadoAtaque:
        token = alvo.encrypt("MENSAGEM_VALIDA_PARA_TESTE")
        prefixo = alvo.prefixo()
        corpo = token[len(prefixo):]

        casos = {
            "vazio": "",
            "só prefixo": prefixo,
            "prefixo errado": "XXX" + corpo,
            "base64 inválido": prefixo + "!!!@@@###",
            "bytes extras no fim": token + "AAAA",
            "bytes extras no início": "AAAA" + token,
        }
        for length in range(1, len(token)):
            casos[f"truncado em {length}"] = token[:length]
        for i in range(20):
            casos[f"lixo aleatório {i}"] = prefixo + random_bytes(16).hex()

        aceitos = []
        for nome, t in casos.items():
            try:
                r = alvo.decrypt(t)
                aceitos.append(f"{nome} -> aceito (retornou {len(r)} bytes)")
            except Exception:
                # comportamento esperado
                pass

        if aceitos:
            return ResultadoAtaque(
                self.nome(),
                True,
                "critica",
                f"{len(aceitos)} entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas",
                {"exemplos": aceitos[:10]},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todas as {len(casos)} entradas malformadas foram rejeitadas",
        )

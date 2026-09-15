"""Um mesmo token não deveria ter múltiplas representações textuais válidas.
Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
token. Isso é "token smuggling": sistemas que comparam/usam a string do
token de formas diferentes (cache, WAF, deduplicação/replay) discordam
sobre o que ele significa.
"""

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueCanonicalizacaoToken:
    def nome(self) -> str:
        return "Canonicalização do token (base64 não-canônico)"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_encode/decode do alvo.")

        texto = "MENSAGEM_DE_TESTE_DE_CANONICALIZACAO"
        token = alvo.encrypt(texto)
        prefixo = alvo.prefixo()
        corpo = token[len(prefixo):]
        meio = len(corpo) // 2

        variantes = {}
        for p in [0, meio, len(corpo) - 1]:
            variantes[f"espaço na posição {p}"] = prefixo + corpo[:p] + " " + corpo[p:]
            variantes[f"newline na posição {p}"] = prefixo + corpo[:p] + "\n" + corpo[p:]
            variantes[f"tab na posição {p}"] = prefixo + corpo[:p] + "\t" + corpo[p:]
        variantes["alfabeto padrão (+/)"] = prefixo + corpo.replace("-", "+").replace("_", "/")
        variantes['padding "=" extra'] = prefixo + corpo + "="
        variantes["caractere inválido no meio"] = prefixo + corpo[:meio] + "!" + corpo[meio:]

        aceitas = []
        for nome, v in variantes.items():
            if v == token:
                continue
            try:
                if alvo.decrypt(v) == texto:
                    aceitas.append(nome)
            except Exception:
                # esperado
                pass

        if aceitas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "media",
                (
                    f"{len(aceitas)} variante(s) textualmente diferente(s) decifram para o mesmo texto: "
                    + "; ".join(aceitas)
                ),
                {"variantes_aceitas": aceitas},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todas as {len(variantes)} variantes não-canônicas foram rejeitadas",
        )

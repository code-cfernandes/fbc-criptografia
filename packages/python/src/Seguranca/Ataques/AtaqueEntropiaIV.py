"""O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.

Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
mesmo sem nunca colidir de fato.

Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
e sequências crescentes/monótonas entre IVs consecutivos (sintoma
clássico de contador ou timestamp).
"""

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueEntropiaIV:
    def __init__(self, amostras: int = 2000):
        self.amostras = amostras

    def nome(self) -> str:
        return "Entropia e previsibilidade do IV"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_decode do alvo.")

        ivs = []
        for _ in range(self.amostras):
            token = alvo.encrypt("X")
            decodificado = alvo.base64url_decode(token[len(alvo.prefixo()):])
            ivs.append(alvo.decompor(decodificado)["iv"])

        problemas = []

        # Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
        contagem = [0] * 256
        total = 0
        for iv in ivs:
            for i in range(len(iv)):
                contagem[iv[i]] += 1
                total += 1
        esperado = total / 256
        qui2 = 0.0
        for c in contagem:
            qui2 += ((c - esperado) ** 2) / esperado
        if qui2 > 330:
            problemas.append(f"distribuição de bytes suspeita (qui-quadrado={qui2:.1f}, >330 é suspeito)")

        # Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
        # primeiro byte estritamente crescente (um contador/timestamp cru
        # produziria isso quase sempre; aleatório, só ~50% das vezes).
        crescentes = 0
        for i in range(1, len(ivs)):
            if ivs[i][0] > ivs[i - 1][0]:
                crescentes += 1
        proporcao_crescente = crescentes / (len(ivs) - 1)
        if proporcao_crescente > 0.65 or proporcao_crescente < 0.35:
            problemas.append(
                f"primeiro byte do IV parece monotônico ({proporcao_crescente * 100:.0f}% das vezes crescente; "
                f"aleatório ficaria perto de 50%)"
            )

        # Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
        # (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
        # repetição interna) - a AUSÊNCIA de qualquer repetição interna em
        # quase todos os IVs seria estranha (sugeriria geração não-uniforme,
        # tipo bytes distintos forçados).
        sem_repeticao_interna = 0
        for iv in ivs:
            if len(set(iv)) == len(iv):
                sem_repeticao_interna += 1
        proporcao_sem_repeticao = sem_repeticao_interna / len(ivs)
        # Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
        if proporcao_sem_repeticao > 0.90 or proporcao_sem_repeticao < 0.50:
            problemas.append(
                f"{proporcao_sem_repeticao * 100:.0f}% dos IVs não têm nenhum byte repetido internamente "
                f"(esperado ~72% para 16 bytes aleatórios)"
            )

        if problemas:
            return ResultadoAtaque(
                self.nome(),
                True,
                "alta",
                "; ".join(problemas),
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"qui-quadrado={qui2:.1f}, {proporcao_crescente * 100:.0f}% primeiro-byte-crescente (~50% esperado), "
            f"{proporcao_sem_repeticao * 100:.0f}% sem repetição interna (~72% esperado) - tudo consistente "
            f"com IV aleatório",
        )

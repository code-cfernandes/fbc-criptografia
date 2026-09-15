"""Se a comparação de integridade não for de tempo constante (ex: usar ==
em vez de hmac.compare_digest()), um atacante consegue medir QUANTOS bytes
iniciais do campo de integridade batem, comparando o tempo de resposta -
e reconstruir a integridade correta byte a byte, sem nunca saber a chave.

Esse teste gera um token válido, cria versões adulteradas onde o campo
de integridade erra em posições DIFERENTES (início vs. fim do campo), e
compara o tempo médio de decrypt() entre os grupos. Uma diferença
estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
último byte" indica uma comparação vulnerável a timing.

IMPORTANTE: testes de timing em Python têm MUITO ruído (garbage collector,
interpretador, agendamento do SO). Isso é uma checagem heurística grosseira,
não uma prova formal - trate qualquer resultado "vulnerável" como um convite
pra investigar o código-fonte diretamente, e um resultado "resistiu" como
"não detectei nesse experimento", não como garantia.
"""

import time

from ..CriptografiaAlvo import CriptografiaAlvo
from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueTiming:
    def __init__(self, repeticoes_por_grupo: int = 400):
        self.repeticoes_por_grupo = repeticoes_por_grupo

    def nome(self) -> str:
        return "Timing da verificação de integridade"

    def executar(self, alvo) -> ResultadoAtaque:
        if not isinstance(alvo, CriptografiaAlvo):
            raise SkipAtaqueException("Precisa de base64url_encode/decode do alvo.")

        token = alvo.encrypt("MENSAGEM_PARA_TESTE_DE_TIMING")
        decodificado = alvo.base64url_decode(token[len(alvo.prefixo()):])
        campos = alvo.decompor(decodificado)
        tamanho_integridade = len(campos["integridade"])

        def medir_grupo(posicao_erro: int) -> int:
            tempos = []
            for r in range(self.repeticoes_por_grupo):
                campos_adulterados = dict(campos)
                integ = bytearray(campos_adulterados["integridade"])
                integ[posicao_erro] ^= 0x01
                campos_adulterados["integridade"] = bytes(integ)

                token_adulterado = alvo.prefixo() + alvo.base64url_encode(
                    alvo.recompor(campos_adulterados)
                )

                inicio = time.perf_counter_ns()
                try:
                    alvo.decrypt(token_adulterado)
                except Exception:
                    # esperado
                    pass
                tempos.append(time.perf_counter_ns() - inicio)
            tempos.sort()
            # usa a mediana em vez da média - muito mais robusta a outliers
            # de agendamento do SO, comum em testes de timing em ambiente
            # compartilhado.
            return tempos[len(tempos) // 2]

        # Grupo A: erro logo no primeiro byte do campo de integridade.
        # Grupo B: erro no último byte.
        # Repete várias rodadas intercaladas pra diluir variação de carga
        # da máquina ao longo do tempo (evita viés de "a máquina esquentou").
        medianas_a = []
        medianas_b = []
        for rodada in range(8):
            medianas_a.append(medir_grupo(0))
            medianas_b.append(medir_grupo(tamanho_integridade - 1))

        mediana_a = sum(medianas_a) / len(medianas_a)
        mediana_b = sum(medianas_b) / len(medianas_b)
        diferenca_relativa = abs(mediana_a - mediana_b) / max(mediana_a, mediana_b)

        # Limite arbitrário e conservador: só marca como suspeito se a
        # diferença for grande o bastante pra não ser só ruído de máquina
        # (na prática, comparações vulneráveis costumam mostrar diferenças
        # bem mais óbvias que isso quando o campo é curto).
        vulneravel = diferenca_relativa > 0.15

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "media" if vulneravel else "info",
            f"mediana erro-no-início={mediana_a:.0f}ns, "
            f"mediana erro-no-fim={mediana_b:.0f}ns, "
            f"diferença relativa={diferenca_relativa * 100:.1f}% (limite=15%). "
            + (
                "Diferença suspeita - investigar se a comparação usa hmac.compare_digest()."
                if vulneravel
                else "Sem diferença clara nesse experimento "
                "(lembrando: teste heurístico, não prova formal)."
            ),
            {"mediana_inicio_ns": mediana_a, "mediana_fim_ns": mediana_b},
        )

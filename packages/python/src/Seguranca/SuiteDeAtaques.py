"""Orquestra a execução de uma coleção de ataques contra um alvo."""

from .ResultadoAtaque import ResultadoAtaque
from .SkipAtaqueException import SkipAtaqueException


class SuiteDeAtaques:
    def __init__(self):
        self._ataques = []

    def adicionar(self, ataque):
        self._ataques.append(ataque)
        return self

    def rodar(self, alvo) -> list:
        resultados = []
        for ataque in self._ataques:
            try:
                resultados.append(ataque.executar(alvo))
            except SkipAtaqueException as e:
                resultados.append(
                    ResultadoAtaque(ataque.nome(), False, "pulado", "Pulado: " + str(e))
                )
            except Exception as e:  # noqa: BLE001 - queremos capturar qualquer falha do ataque
                resultados.append(
                    ResultadoAtaque(ataque.nome(), True, "erro", "Erro ao executar: " + str(e))
                )
        return resultados

    def rodar_e_imprimir(self, alvo) -> bool:
        resultados = self.rodar(alvo)
        vulnerabilidades = 0

        print("=" * 70)
        print("RELATÓRIO DA SUÍTE DE ATAQUES")
        print("=" * 70)
        print()

        for r in resultados:
            print(r.linha_resumo())
            if r.vulneravel and r.severidade not in ("pulado", "demonstracao"):
                vulnerabilidades += 1

        print()
        print("=" * 70)
        if vulnerabilidades == 0:
            print(f"RESUMO: nenhuma vulnerabilidade encontrada em {len(resultados)} ataque(s).")
        else:
            print(
                f"RESUMO: {vulnerabilidades} vulnerabilidade(s) encontrada(s) de "
                f"{len(resultados)} ataque(s) rodados!"
            )
        print("=" * 70)

        return vulnerabilidades == 0

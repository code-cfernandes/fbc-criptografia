from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes, random_int


class AtaqueCoberturaDependencia:
    """
    Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
    de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
    pra evitar falso-positivo por coincidência de valor). Uma dependência
    ausente indica que a mistura não se propagou completamente - um atacante
    poderia isolar e atacar aquele par de posições separadamente do resto.
    """

    def __init__(self, tamanho_bloco: int = 32, perturbacoes_por_par: int = 5):
        self.tamanho_bloco = tamanho_bloco
        self.perturbacoes_por_par = perturbacoes_por_par

    def nome(self) -> str:
        return "Cobertura de dependência (matriz entrada x saída)"

    def executar(self, alvo) -> ResultadoAtaque:
        tamanho = self.tamanho_bloco
        chave_base = b"\x00" * tamanho
        iv = random_bytes(alvo.tamanho_iv())

        ks_base = alvo.gerar_keystream_bruto(chave_base, iv, "enc", tamanho)
        if ks_base is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")
        if len(chave_base) != tamanho:
            # A chave precisa ter o mesmo tamanho do bloco pra esse teste
            # isolar 1 posição de cada vez sem wraparound. Se a cifra usa
            # chave de outro tamanho, pula esse ataque.
            raise SkipAtaqueException("Teste requer chave do mesmo tamanho do bloco.")

        pares_independentes = []

        for pos_entrada in range(tamanho):
            afetou_alguma_saida = [False] * tamanho

            for _ in range(self.perturbacoes_por_par):
                chave_teste = bytearray(chave_base)
                chave_teste[pos_entrada] = random_int(1, 255)
                ks = alvo.gerar_keystream_bruto(chave_teste, iv, "enc", tamanho)

                for pos_saida in range(tamanho):
                    if ks[pos_saida] != ks_base[pos_saida]:
                        afetou_alguma_saida[pos_saida] = True

            for pos_saida, afetou in enumerate(afetou_alguma_saida):
                if not afetou:
                    pares_independentes.append(
                        f"entrada[{pos_entrada}] -> saída[{pos_saida}]"
                    )

        if pares_independentes:
            return ResultadoAtaque(
                self.nome(),
                True,
                "media",
                f"{len(pares_independentes)} par(es) sem dependência detectável em "
                f"{self.perturbacoes_por_par} tentativas cada",
                {"pares": pares_independentes[:20]},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todos os {tamanho * tamanho} pares (entrada, saída) mostraram dependência",
        )

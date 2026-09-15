from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_int


class AtaqueCoberturaDependenciaIV:
    """
    Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
    o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
    posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
    """

    def __init__(self, tamanho_bloco: int = 32, perturbacoes_por_posicao: int = 5):
        self.tamanho_bloco = tamanho_bloco
        self.perturbacoes_por_posicao = perturbacoes_por_posicao

    def nome(self) -> str:
        return "Cobertura de dependência do IV (entrada x saída)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        tamanho_iv = alvo.tamanho_iv()
        iv_base = b"\x00" * tamanho_iv

        ks_base = alvo.gerar_keystream_bruto(chave, iv_base, "enc", self.tamanho_bloco)
        if ks_base is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        pares_independentes = []

        for pos_iv in range(tamanho_iv):
            afetou = [False] * self.tamanho_bloco

            for _ in range(self.perturbacoes_por_posicao):
                iv = bytearray(iv_base)
                iv[pos_iv] = random_int(1, 255)
                ks = alvo.gerar_keystream_bruto(chave, iv, "enc", self.tamanho_bloco)

                for pos_saida in range(self.tamanho_bloco):
                    if ks[pos_saida] != ks_base[pos_saida]:
                        afetou[pos_saida] = True

            for pos_saida, ok in enumerate(afetou):
                if not ok:
                    pares_independentes.append(f"iv[{pos_iv}] -> saida[{pos_saida}]")

        if pares_independentes:
            return ResultadoAtaque(
                self.nome(),
                True,
                "alta",
                f"{len(pares_independentes)} par(es) sem dependência detectável em "
                f"{self.perturbacoes_por_posicao} tentativas cada",
                {"pares": pares_independentes[:20]},
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Todas as {tamanho_iv} posições do IV influenciam todas as "
            f"{self.tamanho_bloco} posições de saída",
        )

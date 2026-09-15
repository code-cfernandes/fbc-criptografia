from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueChavesDegeneradas:
    """
    Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
    (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
    produzir keystream degenerado - e aqui testamos no pior cenário, com IV
    zerado junto, pra isolar a contribuição da chave.
    """

    def __init__(self, tamanho_bloco: int = 32):
        self.tamanho_bloco = tamanho_bloco

    def nome(self) -> str:
        return "Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)"

    def executar(self, alvo) -> ResultadoAtaque:
        tam_chave = len(alvo.chave_de_teste())
        iv_zero = b"\x00" * alvo.tamanho_iv()

        primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste(), iv_zero, "enc", self.tamanho_bloco
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        casos = {
            "zero": b"\x00" * tam_chave,
            "0xFF": b"\xFF" * tam_chave,
            "alternada 0xAA": b"\xAA" * tam_chave,
            "alternada 0x55": b"\x55" * tam_chave,
            'repetida "A"': b"A" * tam_chave,
            "crescente": (bytes(range(256)) * 2)[:tam_chave],
        }

        problemas = {}
        for nome, chave in casos.items():
            ks = alvo.gerar_keystream_bruto(chave, iv_zero, "enc", self.tamanho_bloco)

            metade = self.tamanho_bloco // 2
            periodico = ks[:metade] == ks[metade : metade * 2]
            bytes_unicos = len(set(ks))

            if periodico or bytes_unicos < self.tamanho_bloco * 0.5:
                problemas[nome] = {
                    "periodico": periodico,
                    "bytes_unicos": bytes_unicos,
                }

        if problemas:
            detalhe = "; ".join(
                f"{nome} (periódico={'sim' if info['periodico'] else 'não'}, "
                f"bytes únicos={info['bytes_unicos']}/{self.tamanho_bloco})"
                for nome, info in problemas.items()
            )
            return ResultadoAtaque(
                self.nome(),
                True,
                "alta",
                detalhe,
                problemas,
            )

        return ResultadoAtaque(
            self.nome(),
            False,
            "info",
            f"Nenhuma das {len(casos)} chaves degeneradas testadas produziu saída anômala",
        )

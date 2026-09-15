"""Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
(tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
mesmo quando a maioria das entradas se comporta bem. Testa especificamente
esses casos extremos, que testes com entrada aleatória raramente cobrem.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException


class AtaqueIVsDegenerados:
    def nome(self) -> str:
        return "IVs degenerados (zero, 0xFF, alternado)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        tamanho_iv = alvo.tamanho_iv()
        tamanho_bloco = 32

        primeiro = alvo.gerar_keystream_bruto(
            chave, b"\x00" * tamanho_iv, "enc", tamanho_bloco
        )
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerar_keystream_bruto.")

        casos = {
            "zero": b"\x00" * tamanho_iv,
            "0xFF": b"\xFF" * tamanho_iv,
            "alternado 0xAA": b"\xAA" * tamanho_iv,
            "alternado 0x55": b"\x55" * tamanho_iv,
            "crescente": bytes(range(tamanho_iv)),
        }

        problemas = {}
        for nome, iv in casos.items():
            ks = alvo.gerar_keystream_bruto(chave, iv, "enc", tamanho_bloco)

            metade = tamanho_bloco // 2
            periodico = ks[:metade] == ks[metade : metade * 2]

            bytes_unicos = len(set(ks))
            pouca_variedade = bytes_unicos < tamanho_bloco * 0.5

            if periodico or pouca_variedade:
                problemas[nome] = {
                    "periodico": periodico,
                    "bytes_unicos": bytes_unicos,
                }

        if problemas:
            detalhe = "; ".join(
                f"{nome} (periódico="
                f"{'sim' if info['periodico'] else 'não'}, "
                f"bytes únicos={info['bytes_unicos']}/{tamanho_bloco})"
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
            f"Nenhum dos {len(casos)} IVs degenerados testados produziu "
            "saída anômala",
        )

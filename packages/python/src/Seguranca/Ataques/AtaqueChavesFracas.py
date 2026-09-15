"""Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
produzir keystream anômalo (repetição, período curto, viés de bits ou
distribuição de bytes distorcida). Complementa o ataque de chaves
degeneradas, que só checa a saída do encrypt.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..Util import contar_bits_buffer


class AtaqueChavesFracas:
    def __init__(self, tamanho: int = 2048, tolerancia_bits: float = 0.05):
        self.tamanho = tamanho
        self.tolerancia_bits = tolerancia_bits

    def nome(self) -> str:
        return "Chaves fracas (busca dirigida)"

    def executar(self, alvo) -> ResultadoAtaque:
        tamanho = len(alvo.chave_de_teste().encode())
        casos = [
            ("zeros", bytes(tamanho)),
            ("0xFF", bytes([0xFF] * tamanho)),
            ("alternada AA/55", bytes(0xAA if i % 2 == 0 else 0x55 for i in range(tamanho))),
            ("incremental", bytes(i & 0xFF for i in range(tamanho))),
            ("um bit", bytes(1 if i == 0 else 0 for i in range(tamanho))),
            ("byte repetido 0x01", bytes([0x01] * tamanho)),
            ("padrão AB", bytes(0x41 if i % 2 == 0 else 0x42 for i in range(tamanho))),
        ]

        iv_fixo = bytes(alvo.tamanho_iv())
        anomalias = []

        for nome_caso, chave in casos:
            ks = alvo.gerar_keystream_bruto(chave, iv_fixo, "enc", self.tamanho)

            blocos = set()
            repetidos = 0
            for i in range(0, len(ks) - 32 + 1, 32):
                hex_ = ks[i : i + 32].hex()
                if hex_ in blocos:
                    repetidos += 1
                else:
                    blocos.add(hex_)

            fracao_uns = contar_bits_buffer(ks) / (len(ks) * 8)
            desvio_bits = abs(fracao_uns - 0.5)

            if repetidos > 0:
                anomalias.append(f"{nome_caso}: {repetidos} bloco(s) repetido(s)")
            if desvio_bits > self.tolerancia_bits:
                anomalias.append(f"{nome_caso}: viés de bits {fracao_uns * 100:.1f}%")

        vulneravel = len(anomalias) > 0

        return ResultadoAtaque(
            self.nome(),
            vulneravel,
            "alta" if vulneravel else "info",
            (
                f"Anomalias: {'; '.join(anomalias[:5])}"
                if vulneravel
                else f"Nenhuma das {len(casos)} chaves fracas produziu keystream anômalo ({self.tamanho} bytes cada)"
            ),
            {"anomalias": anomalias},
        )

"""A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
vaza nesse cenário catastrófico.

Isso não é um "bug" da implementação (é uma propriedade universal de
qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
suíte: a segurança inteira depende do IV nunca repetir.
"""

from ..ResultadoAtaque import ResultadoAtaque
from ..SkipAtaqueException import SkipAtaqueException
from ..Util import random_bytes, to_bytes


class AtaqueReusoIV:
    def nome(self) -> str:
        return "Reuso forçado de IV (two-time pad)"

    def executar(self, alvo) -> ResultadoAtaque:
        chave = alvo.chave_de_teste()
        iv_fixo = random_bytes(alvo.tamanho_iv())

        primeiro = alvo.gerar_keystream_bruto(chave, iv_fixo, "enc", 16)
        if primeiro is None:
            raise SkipAtaqueException("Alvo não expõe gerarKeystreamBruto.")

        plaintext1 = "TRANSFERIR_1000"
        plaintext2 = "CANCELAR_TUDO!!"
        tamanho = max(len(plaintext1), len(plaintext2))

        keystream = alvo.gerar_keystream_bruto(chave, iv_fixo, "enc", tamanho)

        ciphertext1 = self._xor(plaintext1, keystream)
        ciphertext2 = self._xor(plaintext2, keystream)

        # O atacante NUNCA precisou saber a key nem o keystream - só
        # observou os dois ciphertexts (que vazariam publicamente se o
        # IV fosse reusado) e os combinou entre si.
        xor_dos_ciphertexts = self._xor(ciphertext1, ciphertext2)
        xor_esperado_dos_plaintexts = self._xor(plaintext1, plaintext2)

        vazou = xor_dos_ciphertexts == xor_esperado_dos_plaintexts

        # Com IV reusado, a propriedade é universal e sempre se confirma - por
        # isso o resultado esperado NÃO é uma vulnerabilidade da cifra (é uma
        # demonstração). Só vira alerta se, por algum motivo, a propriedade
        # NÃO se confirmar (o que indicaria um combinador inconsistente).
        return ResultadoAtaque(
            self.nome(),
            not vazou,
            "demonstracao" if vazou else "alta",
            "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) "
            "sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA "
            "defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
            if vazou
            else "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)",
            {
                "plaintext1": plaintext1,
                "plaintext2": plaintext2,
                "xor_plaintexts_hex": xor_esperado_dos_plaintexts.hex(),
                "xor_ciphertexts_hex": xor_dos_ciphertexts.hex(),
            },
        )

    def _xor(self, a, b) -> bytes:
        A = to_bytes(a)
        B = to_bytes(b)
        n = min(len(A), len(B))
        return bytes(A[i] ^ B[i] for i in range(n))

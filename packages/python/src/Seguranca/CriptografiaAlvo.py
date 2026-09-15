"""Liga a suíte de ataques à implementação real de Criptografia.

Diferente do PHP (que usa Reflection), aqui as camadas internas de keystream
e checksum já são funções públicas do módulo `Criptografia`.
"""

import os

from ..Core import Criptografia
from .Util import to_bytes

CHAVE_PADRAO = "pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf"


class CriptografiaAlvo:
    def __init__(self, chave_teste: str = CHAVE_PADRAO):
        self._chave_teste = chave_teste
        os.environ["FBC_KEY"] = chave_teste

    def encrypt(self, texto: str) -> str:
        return Criptografia.encrypt(texto)

    def decrypt(self, token: str) -> str:
        return Criptografia.decrypt(token)

    def prefixo(self) -> str:
        return "FBC"

    def decompor(self, token_decodificado) -> dict:
        buf = to_bytes(token_decodificado)
        tam_iv = self.tamanho_iv()
        return {
            "integridade": buf[:32],
            "ciphertext": buf[32 : len(buf) - tam_iv],
            "iv": buf[len(buf) - tam_iv :],
        }

    def recompor(self, campos: dict) -> bytes:
        return campos["integridade"] + campos["ciphertext"] + campos["iv"]

    def gerar_keystream_bruto(self, key, iv, proposito: str, tamanho: int) -> bytes:
        return Criptografia.gerar_keystream(to_bytes(key), to_bytes(iv), proposito, tamanho)

    def checksum_bruto(self, dados, key) -> bytes:
        return Criptografia.checksum(to_bytes(dados), to_bytes(key))

    def chave_de_teste(self) -> str:
        return self._chave_teste

    def tamanho_iv(self) -> int:
        return 16

    def base64url_decode(self, data: str) -> bytes:
        return Criptografia.base64url_decode(data)

    def base64url_encode(self, data: bytes) -> str:
        return Criptografia.base64url_encode(data)

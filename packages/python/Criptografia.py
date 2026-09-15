"""
Cifra caseira educacional - porte de Criptografia.php.

Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )

Ver Criptografia.php para os comentários completos sobre o design (difusão
tipo butterfly, distâncias Fibonacci->primo, rotação via Pi). Este arquivo
replica a lógica byte a byte, sem "melhorias" - qualquer mudança de
comportamento aqui quebraria compatibilidade com tokens gerados pelas
versões PHP e Node.js.
"""

import base64
import hmac
import os
import re

TAM_BLOCO = 32

# Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
DISTANCIAS_DIFUSAO = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41]  # dobrado pra combater ataque integral

DIGITOS_PI = (
    "31415926535897932384626433832795028841971693993751058209749445923078"
    "164062862089986280348253421170679"
)


def rot_esquerda8(byte: int, n: int) -> int:
    n &= 7
    if n == 0:
        return byte & 0xFF
    return ((byte << n) | (byte >> (8 - n))) & 0xFF


def rot_esquerda32(val: int, n: int) -> int:
    n &= 31
    val &= 0xFFFFFFFF
    if n == 0:
        return val
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def rotacao_do_round(round_idx: int) -> int:
    d = int(DIGITOS_PI[round_idx % len(DIGITOS_PI)])
    return (d % 7) + 1


def _passo(a: int, b: int, key: bytes, proposito: bytes, pos_fib: int, round_idx: int):
    """Um passo da recorrência tipo-Fibonacci pra uma posição do bloco."""
    n = rotacao_do_round(round_idx)

    soma = (a + b) & 0xFF
    soma = rot_esquerda8(soma, n)
    soma ^= proposito[pos_fib % len(proposito)]
    # A chave participa de CADA rodada, não só do estado inicial (ver
    # comentário equivalente em Criptografia.php).
    soma ^= key[(pos_fib + round_idx) % len(key)]
    soma = (soma * 131) & 0xFF

    return b, soma  # novo a = b antigo; novo b = soma


def gerar_keystream(key: bytes, iv: bytes, proposito: str, tamanho: int) -> bytes:
    """Gera `tamanho` bytes de keystream a partir de KEY + IV + propósito."""
    bloco = TAM_BLOCO
    iv_len = len(iv)
    key_len = len(key)
    proposito_bytes = proposito.encode("utf-8")

    a = [key[pos % key_len] ^ iv[pos % iv_len] for pos in range(bloco)]
    b = [key[(pos + 1) % key_len] ^ iv[(pos + 1) % iv_len] for pos in range(bloco)]

    saida = bytearray()
    round_idx = 0
    pos_fib_base = 0

    while len(saida) < tamanho:
        for dist in DISTANCIAS_DIFUSAO:
            novo_b = [0] * bloco
            for pos in range(bloco):
                a[pos], novo_b[pos] = _passo(
                    a[pos], b[pos], key, proposito_bytes, pos_fib_base + pos, round_idx
                )

            # Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do
            # XOR (ver comentário equivalente no PHP sobre por que isso é
            # essencial - combinação simétrica colapsa metades do bloco).
            misturado = [0] * bloco
            for pos in range(bloco):
                vizinho = novo_b[(pos + dist) % bloco]
                misturado[pos] = rot_esquerda8(novo_b[pos], 1) ^ vizinho
            b = misturado
            round_idx += 1

        pos_fib_base += bloco
        saida.extend(b)

    return bytes(saida[:tamanho])


def _xor_bytes(dados: bytes, keystream: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(dados, keystream))


def checksum(dados: bytes, key: bytes) -> bytes:
    """"MAC" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes."""
    saida = bytearray()
    key_len = len(key)

    for rodada in range(8):
        acumulador = (0x811C9DC5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF

        for i, byte_dado in enumerate(dados):
            byte = byte_dado ^ key[(i + rodada) % key_len]
            acumulador = (acumulador ^ byte) & 0xFFFFFFFF
            acumulador = (acumulador * 16777619) & 0xFFFFFFFF
            acumulador = rot_esquerda32(acumulador, (i % 13) + 1)

        # Finalização: sem isso, o último byte processado só passa por 1
        # multiply+rotate antes de virar saída, e sofre avalanche fraca
        # (medido ~25-30% em vez de ~50% nos últimos bytes do bloco de dados).
        for _ in range(3):
            acumulador ^= acumulador >> 16
            acumulador = (acumulador * 16777619) & 0xFFFFFFFF
            acumulador = rot_esquerda32(acumulador, 13)

        saida.extend(acumulador.to_bytes(4, "big"))

    return bytes(saida)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(data: str) -> bytes:
    if data != "" and not re.fullmatch(r"[A-Za-z0-9_-]+", data):
        raise ValueError("Token contém caracteres inválidos.")

    mod = len(data) % 4
    if mod == 1:
        raise ValueError("Comprimento de token inválido.")
    pad = "=" * (-len(data) % 4)

    decoded = base64.urlsafe_b64decode(data + pad)

    # Canonicidade: reencoda e compara - pega bits não-canônicos no último
    # grupo que sobreviveriam mesmo a uma decodificação "estrita".
    if base64url_encode(decoded) != data:
        raise ValueError("Token não está em forma canônica.")

    return decoded


def _get_key() -> bytes:
    key = os.environ.get("FBC_KEY", "")
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 32:
        raise ValueError("Chave deve ter 32 bytes.")
    return key_bytes


def encrypt(text: str) -> str:
    key = _get_key()
    iv = os.urandom(16)
    text_bytes = text.encode("utf-8")

    enc_keystream = gerar_keystream(key, iv, "enc", len(text_bytes))
    ciphertext = _xor_bytes(text_bytes, enc_keystream)

    mac_key = gerar_keystream(key, iv, "mac", TAM_BLOCO)
    integridade = checksum(iv + ciphertext, mac_key)

    return "FBC" + base64url_encode(integridade + ciphertext + iv)


def decrypt(text: str) -> str:
    if text[:3] != "FBC":
        raise ValueError("Invalid text. Text must start with FBC.")

    key = _get_key()
    decoded = base64url_decode(text[3:])

    integridade_recebida = decoded[:TAM_BLOCO]
    iv = decoded[-16:]
    ciphertext = decoded[TAM_BLOCO:-16]

    mac_key = gerar_keystream(key, iv, "mac", TAM_BLOCO)
    integridade_esperada = checksum(iv + ciphertext, mac_key)

    if not hmac.compare_digest(integridade_esperada, integridade_recebida):
        raise ValueError("Token adulterado ou chave incorreta.")

    enc_keystream = gerar_keystream(key, iv, "enc", len(ciphertext))
    return _xor_bytes(ciphertext, enc_keystream).decode("utf-8")
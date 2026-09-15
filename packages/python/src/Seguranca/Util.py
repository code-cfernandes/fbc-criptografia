"""Funções utilitárias compartilhadas pelos ataques."""

import os
import random


def random_int(minimo: int, maximo: int) -> int:
    """Inteiro aleatório em [minimo, maximo], inclusivo (random_int do PHP)."""
    return random.randint(minimo, maximo)


def random_bytes(n: int) -> bytes:
    """N bytes aleatórios (random_bytes do PHP)."""
    return os.urandom(n)


def to_bytes(valor) -> bytes:
    """Converte bytes/bytearray/str para bytes."""
    if isinstance(valor, bytes):
        return valor
    if isinstance(valor, bytearray):
        return bytes(valor)
    return valor.encode("utf-8")


def contar_bits1(byte: int) -> int:
    """Popcount de um byte (0-255)."""
    return bin(byte & 0xFF).count("1")


def contar_bits_buffer(buf: bytes) -> int:
    """Popcount total de um buffer."""
    return sum(contar_bits1(b) for b in buf)


def bits_diferentes(a, b) -> int:
    """Conta quantos bits diferem entre dois buffers de mesmo tamanho."""
    A = to_bytes(a)
    B = to_bytes(b)
    return sum(contar_bits1(x ^ y) for x, y in zip(A, B))


def shuffle(lista: list) -> list:
    """Fisher-Yates: retorna uma cópia embaralhada da lista."""
    copia = list(lista)
    random.shuffle(copia)
    return copia


def array_rand_key(dicionario: dict):
    """Chave aleatória de um dicionário (array_rand do PHP)."""
    return random.choice(list(dicionario.keys()))

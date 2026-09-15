#!/usr/bin/env python3
"""Harness de regressão histórica.

Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
(vulneravel=True). Em seguida o mesmo ataque roda contra o código atual e
PRECISA resistir (vulneravel=False).
"""

import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.Core import Criptografia
from src.Seguranca.CriptografiaAlvo import CriptografiaAlvo

from src.Seguranca.Ataques.AtaqueCorrelacaoMesmoPlaintext import AtaqueCorrelacaoMesmoPlaintext
from src.Seguranca.Ataques.AtaqueFoldEstrutural import AtaqueFoldEstrutural
from src.Seguranca.Ataques.AtaqueAvalancheChecksum import AtaqueAvalancheChecksum
from src.Seguranca.Ataques.AtaqueIntegral import AtaqueIntegral
from src.Seguranca.Ataques.AtaqueSeparacaoChaveIV import AtaqueSeparacaoChaveIV
from src.Seguranca.Ataques.AtaqueCanonicalizacaoToken import AtaqueCanonicalizacaoToken

TAM_BLOCO = 32
DIGITOS_PI = (
    "31415926535897932384626433832795028841971693993751058209749445923078"
    "164062862089986280348253421170679"
)


def rot_esquerda8(byte: int, n: int) -> int:
    n &= 7
    if n == 0:
        return byte & 0xFF
    return ((byte << n) | (byte >> (8 - n))) & 0xFF


def rotacao_do_round(round_idx: int) -> int:
    d = int(DIGITOS_PI[round_idx % len(DIGITOS_PI)])
    return (d % 7) + 1


def passo_com_bug(bug, a, b, key_buf, proposito_buf, pos_fib, round_idx):
    """passo com mutações: bug 5 remove a reinserção da chave em cada rodada."""
    n = rotacao_do_round(round_idx)
    soma = (a + b) & 0xFF
    soma = rot_esquerda8(soma, n)
    soma ^= proposito_buf[pos_fib % len(proposito_buf)]
    if bug != 5:
        soma ^= key_buf[(pos_fib + round_idx) % len(key_buf)]
    soma = (soma * 131) & 0xFF
    return b, soma


def gerar_keystream_com_bug(bug, key_buf, iv_buf, proposito, tamanho):
    """gerarKeystream com mutações: bugs 1, 2, 4, 5."""
    if bug == 1:
        # bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
        return Criptografia.gerar_keystream(key_buf, bytes(len(iv_buf)), proposito, tamanho)

    bloco = TAM_BLOCO
    # bug 2: o colapso de metades só acontece quando a distância é exatamente
    # metade do bloco (16) — reproduzimos a condição histórica.
    if bug == 4:
        distancias = [3]
    elif bug == 2:
        distancias = [3, 5, 11, 19, 41, 16]
    else:
        distancias = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41]

    iv_len = len(iv_buf)
    key_len = len(key_buf)
    proposito_buf = proposito.encode("utf-8")

    a = [key_buf[pos % key_len] ^ iv_buf[pos % iv_len] for pos in range(bloco)]
    b = [key_buf[(pos + 1) % key_len] ^ iv_buf[(pos + 1) % iv_len] for pos in range(bloco)]

    partes = bytearray()
    total_gerado = 0
    round_idx = 0
    pos_fib_base = 0

    while total_gerado < tamanho:
        for dist in distancias:
            novo_b = [0] * bloco
            for pos in range(bloco):
                a[pos], novo_b[pos] = passo_com_bug(
                    bug, a[pos], b[pos], key_buf, proposito_buf, pos_fib_base + pos, round_idx
                )
            misturado = [0] * bloco
            for pos in range(bloco):
                vizinho = novo_b[(pos + dist) % bloco]
                if bug == 2:
                    # bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                    misturado[pos] = rot_esquerda8(novo_b[pos] ^ vizinho, 1)
                else:
                    misturado[pos] = rot_esquerda8(novo_b[pos], 1) ^ vizinho
            b = misturado
            round_idx += 1
        pos_fib_base += bloco
        partes.extend(b)
        total_gerado += bloco

    return bytes(partes[:tamanho])


def checksum_com_bug(bug, dados_buf, key_buf):
    """checksum com mutação: bug 3 remove a finalização."""
    saida = bytearray()
    key_len = len(key_buf)
    for rodada in range(8):
        acumulador = (0x811C9DC5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF
        for i, byte_dado in enumerate(dados_buf):
            byte = byte_dado ^ key_buf[(i + rodada) % key_len]
            acumulador = (acumulador ^ byte) & 0xFFFFFFFF
            acumulador = (acumulador * 16777619) & 0xFFFFFFFF
            acumulador = Criptografia.rot_esquerda32(acumulador, (i % 13) + 1)
        if bug != 3:
            for _ in range(3):
                acumulador ^= acumulador >> 16
                acumulador = (acumulador * 16777619) & 0xFFFFFFFF
                acumulador = Criptografia.rot_esquerda32(acumulador, 13)
        saida.extend(acumulador.to_bytes(4, "big"))
    return bytes(saida)


def base64url_decode_com_bug(bug, data):
    """base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo."""
    if bug != 6:
        return Criptografia.base64url_decode(data)
    s = data.replace("-", "+").replace("_", "/")
    s = re.sub(r"[^A-Za-z0-9+/]", "", s)
    mod = len(s) % 4
    if mod == 1:
        s = s[:-1]
        mod = 0
    if mod:
        s += "=" * (4 - mod)
    return base64.b64decode(s)


class SnapshotAlvo(CriptografiaAlvo):
    """Alvo que aponta para a cifra com o bug selecionado."""

    def __init__(self, bug):
        super().__init__()
        self.bug = bug

    def gerar_keystream_bruto(self, key, iv, proposito, tamanho):
        key_buf = key if isinstance(key, (bytes, bytearray)) else key.encode("utf-8")
        iv_buf = iv if isinstance(iv, (bytes, bytearray)) else iv.encode("binary")
        return gerar_keystream_com_bug(
            self.bug, bytes(key_buf), bytes(iv_buf), proposito, tamanho
        )

    def checksum_bruto(self, dados, key):
        dados_buf = dados if isinstance(dados, (bytes, bytearray)) else dados.encode("binary")
        key_buf = key if isinstance(key, (bytes, bytearray)) else key.encode("binary")
        return checksum_com_bug(self.bug, bytes(dados_buf), bytes(key_buf))

    def base64url_decode(self, data):
        return base64url_decode_com_bug(self.bug, data)

    def encrypt(self, texto):
        key = self.chave_de_teste().encode("utf-8")
        iv = os.urandom(16)
        text_bytes = texto.encode("utf-8")
        ks = self.gerar_keystream_bruto(key, iv, "enc", len(text_bytes))
        ct = bytes(t ^ k for t, k in zip(text_bytes, ks))
        mac_key = self.gerar_keystream_bruto(key, iv, "mac", 32)
        integridade = self.checksum_bruto(iv + ct, mac_key)
        return "FBC" + Criptografia.base64url_encode(integridade + ct + iv)

    def decrypt(self, token):
        if token[:3] != "FBC":
            raise ValueError("prefixo")
        key = self.chave_de_teste().encode("utf-8")
        decoded = self.base64url_decode(token[3:])
        integ = decoded[:32]
        iv = decoded[-16:]
        ct = decoded[32:-16]
        mac_key = self.gerar_keystream_bruto(key, iv, "mac", 32)
        esperado = self.checksum_bruto(iv + ct, mac_key)
        if esperado != integ:
            raise ValueError("MAC")
        ks = self.gerar_keystream_bruto(key, iv, "enc", len(ct))
        return bytes(c ^ k for c, k in zip(ct, ks)).decode("utf-8")


CASOS = [
    {"bug": 1, "descricao": "keystream ignora o IV", "ataque": AtaqueCorrelacaoMesmoPlaintext()},
    {
        "bug": 2,
        "descricao": "combinador simétrico (metades colapsam)",
        "ataque": AtaqueFoldEstrutural(),
    },
    {"bug": 3, "descricao": "checksum sem finalização", "ataque": AtaqueAvalancheChecksum()},
    {"bug": 4, "descricao": "cinco rodadas de difusão", "ataque": AtaqueIntegral()},
    {"bug": 5, "descricao": "chave só no estado inicial", "ataque": AtaqueSeparacaoChaveIV()},
    {"bug": 6, "descricao": "base64 não estrito", "ataque": AtaqueCanonicalizacaoToken()},
]


def main() -> int:
    print("=" * 72)
    print("REGRESSÃO HISTÓRICA")
    print("=" * 72)

    falhas = 0
    for caso in CASOS:
        snapshot = SnapshotAlvo(caso["bug"])
        real = CriptografiaAlvo()

        try:
            r_snapshot = caso["ataque"].executar(snapshot)
            r_real = caso["ataque"].executar(real)
        except Exception as e:  # noqa: BLE001
            print(f"  ❌ bug {caso['bug']} ({caso['descricao']}): erro — {e}")
            falhas += 1
            continue

        detectou = r_snapshot.vulneravel is True
        resistiu = r_real.vulneravel is False
        ok = detectou and resistiu
        if not ok:
            falhas += 1

        print(
            f"  {'✅' if ok else '❌'} bug {caso['bug']} ({caso['descricao']}): "
            f"snapshot {'detectado' if detectou else 'NÃO detectado'} | "
            f"atual {'resistiu' if resistiu else 'ACUSOU'}"
        )
        if not ok:
            print(f"       snapshot: {r_snapshot.linha_resumo()}")
            print(f"       atual:    {r_real.linha_resumo()}")

    print("=" * 72)
    if falhas == 0:
        print(f"RESUMO: {len(CASOS)} bugs históricos detectados; código atual resiste a todos.")
    else:
        print(f"RESUMO: {falhas} caso(s) falharam.")
    print("=" * 72)

    return 0 if falhas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

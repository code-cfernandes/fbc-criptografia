#!/usr/bin/env python3
"""Roda a suíte de ataques contra a implementação Python da cifra."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.Seguranca.CriptografiaAlvo import CriptografiaAlvo
from src.Seguranca.SuiteDeAtaques import SuiteDeAtaques

from src.Seguranca.Ataques.AtaqueIdaEVolta import AtaqueIdaEVolta
from src.Seguranca.Ataques.AtaqueAdulteracao import AtaqueAdulteracao
from src.Seguranca.Ataques.AtaqueColisaoIV import AtaqueColisaoIV
from src.Seguranca.Ataques.AtaqueBytesFixos import AtaqueBytesFixos
from src.Seguranca.Ataques.AtaqueAvalanche import AtaqueAvalanche
from src.Seguranca.Ataques.AtaqueDistribuicaoBytes import AtaqueDistribuicaoBytes
from src.Seguranca.Ataques.AtaqueFoldEstrutural import AtaqueFoldEstrutural
from src.Seguranca.Ataques.AtaqueCoberturaDependencia import AtaqueCoberturaDependencia
from src.Seguranca.Ataques.AtaqueIVsDegenerados import AtaqueIVsDegenerados
from src.Seguranca.Ataques.AtaqueCorrelacaoMesmoPlaintext import AtaqueCorrelacaoMesmoPlaintext
from src.Seguranca.Ataques.AtaqueReusoIV import AtaqueReusoIV
from src.Seguranca.Ataques.AtaqueVetorDeterministico import AtaqueVetorDeterministico
from src.Seguranca.Ataques.AtaqueTiming import AtaqueTiming
from src.Seguranca.Ataques.AtaqueColisaoChecksum import AtaqueColisaoChecksum
from src.Seguranca.Ataques.AtaqueEntropiaIV import AtaqueEntropiaIV
from src.Seguranca.Ataques.AtaqueAvalancheChave import AtaqueAvalancheChave
from src.Seguranca.Ataques.AtaqueAvalancheChecksum import AtaqueAvalancheChecksum
from src.Seguranca.Ataques.AtaqueIndependenciaProposito import AtaqueIndependenciaProposito
from src.Seguranca.Ataques.AtaqueAutocorrelacao import AtaqueAutocorrelacao
from src.Seguranca.Ataques.AtaqueTokensMalformados import AtaqueTokensMalformados
from src.Seguranca.Ataques.AtaqueChaveErrada import AtaqueChaveErrada
from src.Seguranca.Ataques.AtaqueComplexidadeLinear import AtaqueComplexidadeLinear
from src.Seguranca.Ataques.AtaqueBateriaEstatistica import AtaqueBateriaEstatistica
from src.Seguranca.Ataques.AtaqueCanonicalizacaoToken import AtaqueCanonicalizacaoToken
from src.Seguranca.Ataques.AtaqueCoberturaDependenciaIV import AtaqueCoberturaDependenciaIV
from src.Seguranca.Ataques.AtaqueSeparacaoChaveIV import AtaqueSeparacaoChaveIV
from src.Seguranca.Ataques.AtaqueChavesDegeneradas import AtaqueChavesDegeneradas
from src.Seguranca.Ataques.AtaqueSerialBits import AtaqueSerialBits
from src.Seguranca.Ataques.AtaqueCusum import AtaqueCusum
from src.Seguranca.Ataques.AtaqueEntropiaAproximada import AtaqueEntropiaAproximada
from src.Seguranca.Ataques.AtaqueMensagemLonga import AtaqueMensagemLonga
from src.Seguranca.Ataques.AtaqueIdaEVoltaBinario import AtaqueIdaEVoltaBinario
from src.Seguranca.Ataques.AtaqueConfusaoCampos import AtaqueConfusaoCampos
from src.Seguranca.Ataques.AtaqueLinearidadeChecksum import AtaqueLinearidadeChecksum
from src.Seguranca.Ataques.AtaqueValidacaoChave import AtaqueValidacaoChave
from src.Seguranca.Ataques.AtaqueIntegral import AtaqueIntegral
from src.Seguranca.Ataques.AtaqueDiferencialKeystream import AtaqueDiferencialKeystream
from src.Seguranca.Ataques.AtaqueDistribuicaoPorPosicao import AtaqueDistribuicaoPorPosicao
from src.Seguranca.Ataques.AtaqueCorrelacaoPosicoes import AtaqueCorrelacaoPosicoes
from src.Seguranca.Ataques.AtaquePreditorDeBits import AtaquePreditorDeBits


def main() -> int:
    alvo = CriptografiaAlvo()

    suite = SuiteDeAtaques()
    (
        suite.adicionar(AtaqueIdaEVolta())
        .adicionar(AtaqueAdulteracao())
        .adicionar(AtaqueColisaoIV())
        .adicionar(AtaqueBytesFixos())
        .adicionar(AtaqueAvalanche())
        .adicionar(AtaqueDistribuicaoBytes())
        .adicionar(AtaqueFoldEstrutural())
        .adicionar(AtaqueCoberturaDependencia())
        .adicionar(AtaqueIVsDegenerados())
        .adicionar(AtaqueCorrelacaoMesmoPlaintext())
        .adicionar(AtaqueReusoIV())
        .adicionar(AtaqueVetorDeterministico())
        .adicionar(AtaqueTiming())
        .adicionar(AtaqueColisaoChecksum())
        .adicionar(AtaqueEntropiaIV())
        .adicionar(AtaqueAvalancheChave())
        .adicionar(AtaqueAvalancheChecksum())
        .adicionar(AtaqueIndependenciaProposito())
        .adicionar(AtaqueAutocorrelacao())
        .adicionar(AtaqueTokensMalformados())
        .adicionar(AtaqueChaveErrada())
        .adicionar(AtaqueComplexidadeLinear())
        .adicionar(AtaqueBateriaEstatistica())
        .adicionar(AtaqueCanonicalizacaoToken())
        .adicionar(AtaqueCoberturaDependenciaIV())
        .adicionar(AtaqueSeparacaoChaveIV())
        .adicionar(AtaqueChavesDegeneradas())
        .adicionar(AtaqueSerialBits())
        .adicionar(AtaqueCusum())
        .adicionar(AtaqueEntropiaAproximada())
        .adicionar(AtaqueMensagemLonga())
        .adicionar(AtaqueIdaEVoltaBinario())
        .adicionar(AtaqueConfusaoCampos())
        .adicionar(AtaqueLinearidadeChecksum())
        .adicionar(AtaqueValidacaoChave())
        .adicionar(AtaqueIntegral())
        .adicionar(AtaqueDiferencialKeystream())
        .adicionar(AtaqueDistribuicaoPorPosicao())
        .adicionar(AtaqueCorrelacaoPosicoes())
        .adicionar(AtaquePreditorDeBits())
    )

    passou = suite.rodar_e_imprimir(alvo)
    return 0 if passou else 1


if __name__ == "__main__":
    sys.exit(main())

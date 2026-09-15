#!/usr/bin/env julia
"""Roda a suíte de ataques contra a implementação Julia da cifra FBC."""

include(joinpath(@__DIR__, "..", "src", "CriptografiaFBC.jl"))
using .CriptografiaFBC

alvo = CriptografiaAlvo()

suite = SuiteDeAtaques()
adicionar(suite, AtaqueIdaEVolta())
adicionar(suite, AtaqueAdulteracao())
adicionar(suite, AtaqueVetorDeterministico())
adicionar(suite, AtaqueInteroperabilidade())
adicionar(suite, AtaqueColisaoIV())
adicionar(suite, AtaqueBytesFixos())
adicionar(suite, AtaqueChaveErrada())
adicionar(suite, AtaqueValidacaoChave())

passou = rodar_e_imprimir(suite, alvo)

exit(passou ? 0 : 1)

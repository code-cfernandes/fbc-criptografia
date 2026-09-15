#!/usr/bin/env julia
"""Runner de fuzzing cruzado: gera keystreams e checksums brutos a partir de
fuzz/casos.txt para comparação com as demais implementações.

uso: julia --startup-file=no bin/fuzz_cruzado.jl <entrada> <saida>
"""

include(joinpath(@__DIR__, "..", "src", "CriptografiaFBC.jl"))
using .CriptografiaFBC

function main()
    if length(ARGS) < 2
        println(stderr, "uso: julia --startup-file=no bin/fuzz_cruzado.jl <entrada> <saida>")
        exit(1)
    end

    caminho_entrada, caminho_saida = ARGS[1], ARGS[2]

    linhas = String[]
    for linha in eachline(caminho_entrada)
        linha = strip(linha)
        isempty(linha) || push!(linhas, linha)
    end

    alvo = CriptografiaAlvo()
    saida = String[]

    for (indice, linha) in enumerate(linhas)
        partes = split(linha, '|'; keepempty=true)
        if length(partes) < 4
            println(stderr, "Linha malformada no índice $(indice - 1): $(linha)")
            exit(1)
        end

        chave = hex2bytes(partes[1])
        iv = hex2bytes(partes[2])
        proposito = partes[3]
        plaintext = hex2bytes(partes[4])

        ks = gerar_keystream_bruto(alvo, chave, iv, proposito, length(plaintext))
        mac = checksum_bruto(alvo, plaintext, chave)

        push!(saida, "$(indice - 1)|$(bytes2hex(ks))|$(bytes2hex(mac))")
    end

    open(caminho_saida, "w") do arquivo
        for linha in saida
            println(arquivo, linha)
        end
    end
end

main()

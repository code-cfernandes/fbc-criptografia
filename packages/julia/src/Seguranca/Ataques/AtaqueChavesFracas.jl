"""
Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
produzir keystream anômalo (repetição, período curto, viés de bits ou
distribuição de bytes distorcida). Complementa o ataque de chaves degeneradas,
que só checa a saída do encrypt.
"""
struct AtaqueChavesFracas <: Ataque
    tamanho::Int
    tolerancia_bits::Float64
end

AtaqueChavesFracas(; tamanho::Integer = 2048, tolerancia_bits::Real = 0.05) =
    AtaqueChavesFracas(Int(tamanho), Float64(tolerancia_bits))

nome(::AtaqueChavesFracas) = "Chaves fracas (busca dirigida)"

function executar(a::AtaqueChavesFracas, alvo::AlvoCriptografico)
    len = length(codeunits(chave_de_teste(alvo)))

    casos = Pair{String,Vector{UInt8}}[
        "zeros" => zeros(UInt8, len),
        "0xFF" => fill(0xff, len),
        "alternada AA/55" => UInt8[i % 2 == 0 ? 0xaa : 0x55 for i in 0:(len-1)],
        "incremental" => UInt8[i & 0xff for i in 0:(len-1)],
        "um bit" => UInt8[i == 0 ? 1 : 0 for i in 0:(len-1)],
        "byte repetido 0x01" => fill(0x01, len),
        "padrão AB" => UInt8[i % 2 == 0 ? 0x41 : 0x42 for i in 0:(len-1)],
    ]

    iv_fixo = zeros(UInt8, tamanho_iv(alvo))
    anomalias = String[]

    for (nome_caso, chave) in casos
        ks = gerar_keystream_bruto(alvo, chave, iv_fixo, "enc", a.tamanho)

        blocos = Set{String}()
        repetidos = 0
        for i in 0:32:(length(ks)-32)
            hex = bytes2hex(ks[i+1:i+32])
            if hex in blocos
                repetidos += 1
            else
                push!(blocos, hex)
            end
        end

        fracao_uns = contar_bits_buffer(ks) / (length(ks) * 8)
        desvio_bits = abs(fracao_uns - 0.5)

        if repetidos > 0
            push!(anomalias, "$nome_caso: $repetidos bloco(s) repetido(s)")
        end
        if desvio_bits > a.tolerancia_bits
            push!(anomalias, "$nome_caso: viés de bits $(fmt(fracao_uns * 100, 1))%")
        end
    end

    vulneravel = !isempty(anomalias)

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        vulneravel ?
        "Anomalias: $(join(anomalias[1:min(5, length(anomalias))], "; "))" :
        "Nenhuma das $(length(casos)) chaves fracas produziu keystream anômalo ($(a.tamanho) bytes cada)",
        Dict{String,Any}("anomalias" => anomalias),
    )
end

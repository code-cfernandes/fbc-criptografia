"""
Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
0xFF, complemento) não devem gerar keystreams correlacionados. Um key schedule
fraco faz `keystream(key)` e `keystream(key ^ delta)` compartilharem estrutura
(distância de Hamming baixa).
"""
struct AtaqueChaveRelacionada <: Ataque
    tamanho_bloco::Int
    iv_por_delta::Int
    limite_media::Float64
    limite_pior::Float64
end

AtaqueChaveRelacionada(;
    tamanho_bloco::Integer = 32,
    iv_por_delta::Integer = 3,
    limite_media::Real = 0.45,
    limite_pior::Real = 0.3,
) = AtaqueChaveRelacionada(
    Int(tamanho_bloco),
    Int(iv_por_delta),
    Float64(limite_media),
    Float64(limite_pior),
)

nome(::AtaqueChaveRelacionada) = "Chave relacionada (related-key)"

function executar(a::AtaqueChaveRelacionada, alvo::AlvoCriptografico)
    chave_base = to_buffer(chave_de_teste(alvo))
    len = length(chave_base)

    deltas = Vector{UInt8}[]
    for i in 0:(len-1)
        d = zeros(UInt8, len)
        d[i+1] = 0x01
        push!(deltas, d)
    end
    for i in 0:(len-1)
        d = zeros(UInt8, len)
        d[i+1] = 0xff
        push!(deltas, d)
    end
    push!(deltas, chave_base .⊻ UInt8(0xff))

    valores = Float64[]
    total_bits = a.tamanho_bloco * 8

    for delta in deltas
        chave_relacionada = chave_base .⊻ delta
        for _ in 1:(a.iv_por_delta)
            iv = random_bytes(tamanho_iv(alvo))
            ks1 = gerar_keystream_bruto(alvo, chave_base, iv, "enc", a.tamanho_bloco)
            ks2 = gerar_keystream_bruto(alvo, chave_relacionada, iv, "enc", a.tamanho_bloco)
            push!(valores, bits_diferentes(ks1, ks2) / total_bits)
        end
    end

    media = sum(valores) / length(valores)
    pior = minimum(valores)
    vulneravel = media < a.limite_media || pior < a.limite_pior

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "média=$(fmt(media * 100, 1))%, pior=$(fmt(pior * 100, 1))% em $(length(valores)) pares (limites: média>=$(fmt(a.limite_media * 100, 0))%, pior>=$(fmt(a.limite_pior * 100, 0))%)",
        Dict{String,Any}("media" => media, "pior" => pior),
    )
end

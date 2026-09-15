"""
Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
seria atacável resolvendo um sistema linear em vez de força bruta.
"""
struct AtaqueComplexidadeLinear <: Ataque
    bits_por_amostra::Int
    amostras::Int
    limite_relativo::Float64
end

AtaqueComplexidadeLinear(;
    bits_por_amostra::Integer = 1024,
    amostras::Integer = 5,
    limite_relativo::Real = 0.4,
) = AtaqueComplexidadeLinear(
    Int(bits_por_amostra),
    Int(amostras),
    Float64(limite_relativo),
)

nome(::AtaqueComplexidadeLinear) = "Complexidade linear (Berlekamp-Massey)"

function _bits_msb_limitado(bytes::AbstractVector{UInt8}, limite::Integer)
    bits = Int[]
    for i in 1:length(bytes)
        length(bits) >= limite && break
        byte = bytes[i]
        for b in 7:-1:0
            push!(bits, Int((byte >> b) & 0x01))
        end
    end
    return bits[1:min(limite, length(bits))]
end

"""Algoritmo de Berlekamp-Massey sobre GF(2)."""
function _berlekamp_massey(s::AbstractVector{<:Integer})
    n = length(s)
    c = zeros(Int, n)
    c[1] = 1
    b = zeros(Int, n)
    b[1] = 1
    l = 0
    m = -1

    for i in 0:(n-1)
        d = s[i+1]
        for j in 1:l
            d ⊻= c[j+1] & s[i-j+1]
        end

        if d == 1
            t = copy(c)
            shift = i - m
            for j in 0:(n-1)
                j + shift >= n && break
                c[j+shift+1] ⊻= b[j+1]
            end
            if l <= fld(i, 2)
                l = i + 1 - l
                m = i
                copyto!(b, t)
            end
        end
    end

    return l
end

function executar(a::AtaqueComplexidadeLinear, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)

    relativos = Float64[]
    pior = 1.0
    for _ in 1:(a.amostras)
        bytes = gerar_keystream_bruto(
            alvo,
            chave,
            random_bytes(tamanho_iv(alvo)),
            "enc",
            div(a.bits_por_amostra, 8),
        )
        bits = _bits_msb_limitado(bytes, a.bits_por_amostra)
        relativo = _berlekamp_massey(bits) / a.bits_por_amostra
        push!(relativos, relativo)
        pior = min(pior, relativo)
    end

    media = sum(relativos) / length(relativos)
    vulneravel = pior < a.limite_relativo

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        "complexidade linear relativa: média=$(fmt(media * 100, 1))%, pior=$(fmt(pior * 100, 1))% de $(a.bits_por_amostra) bits (esperado ~50%; limite>=$(fmt(a.limite_relativo * 100, 0))%)",
        Dict{String,Any}("media" => media, "pior" => pior),
    )
end

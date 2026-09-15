"""
O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
Números baixos indicam que parte da chave tem pouca influência - o que
reduziria o espaço de busca de um atacante.
"""
struct AtaqueAvalancheChave <: Ataque
    amostras::Int
    tamanho_bloco::Int
    limite_media::Float64
    limite_pior_caso::Float64
end

AtaqueAvalancheChave(;
    amostras::Integer = 3000,
    tamanho_bloco::Integer = 32,
    limite_media::Real = 0.45,
    limite_pior_caso::Real = 0.3,
) = AtaqueAvalancheChave(
    Int(amostras),
    Int(tamanho_bloco),
    Float64(limite_media),
    Float64(limite_pior_caso),
)

nome(::AtaqueAvalancheChave) = "Efeito avalanche da chave"

function executar(a::AtaqueAvalancheChave, alvo::AlvoCriptografico)
    chave_base = to_buffer(chave_de_teste(alvo))
    len_chave = length(chave_base)
    iv = random_bytes(tamanho_iv(alvo))

    valores = Float64[]
    for _ in 1:(a.amostras)
        chave = copy(chave_base)
        pos = random_int(0, len_chave - 1)
        chave[pos+1] = chave[pos+1] ⊻ UInt8(1 << random_int(0, 7))

        ks1 = gerar_keystream_bruto(alvo, chave_base, iv, "enc", a.tamanho_bloco)
        ks2 = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho_bloco)

        push!(valores, bits_diferentes(ks1, ks2) / (a.tamanho_bloco * 8))
    end

    sort!(valores)
    n = length(valores)
    media = sum(valores) / n
    pior_caso = valores[1]

    vulneravel = media < a.limite_media || pior_caso < a.limite_pior_caso

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "média=$(fmt(media * 100, 1))%, pior caso=$(fmt(pior_caso * 100, 1))% (limites: média>=$(fmt(a.limite_media * 100, 0))%, pior>=$(fmt(a.limite_pior_caso * 100, 0))%)",
        Dict{String,Any}("media" => media, "pior_caso" => pior_caso),
    )
end

"""
Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
gerado (efeito avalanche). Números muito abaixo disso indicam difusão
fraca - foi o que achamos quando o número de rodadas de mistura era
baixo demais numa das versões anteriores.
"""
struct AtaqueAvalanche <: Ataque
    amostras::Int
    tamanho_bloco::Int
    limite_media::Float64
    limite_pior_caso::Float64
end

AtaqueAvalanche(;
    amostras::Integer = 3000,
    tamanho_bloco::Integer = 32,
    limite_media::Real = 0.45,
    limite_pior_caso::Real = 0.3,
) = AtaqueAvalanche(
    Int(amostras),
    Int(tamanho_bloco),
    Float64(limite_media),
    Float64(limite_pior_caso),
)

nome(::AtaqueAvalanche) = "Efeito avalanche"

function executar(a::AtaqueAvalanche, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)
    tam_iv = tamanho_iv(alvo)

    valores = Float64[]
    for _ in 1:(a.amostras)
        iv1 = random_bytes(tam_iv)
        iv2 = copy(iv1)
        pos = random_int(0, tam_iv - 1)
        iv2[pos+1] = iv2[pos+1] ⊻ UInt8(1 << random_int(0, 7))

        ks1 = gerar_keystream_bruto(alvo, chave, iv1, "enc", a.tamanho_bloco)
        ks2 = gerar_keystream_bruto(alvo, chave, iv2, "enc", a.tamanho_bloco)

        push!(valores, bits_diferentes(ks1, ks2) / (a.tamanho_bloco * 8))
    end

    sort!(valores)
    n = length(valores)
    media = sum(valores) / n
    pior_caso = valores[1]
    percentil1 = valores[trunc(Int, n * 0.01)+1]

    vulneravel = media < a.limite_media || pior_caso < a.limite_pior_caso

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "média=$(fmt(media * 100, 1))%, pior caso=$(fmt(pior_caso * 100, 1))%, percentil 1%=$(fmt(percentil1 * 100, 1))% (limites: média>=$(fmt(a.limite_media * 100, 0))%, pior>=$(fmt(a.limite_pior_caso * 100, 0))%)",
        Dict{String,Any}("media" => media, "pior_caso" => pior_caso),
    )
end

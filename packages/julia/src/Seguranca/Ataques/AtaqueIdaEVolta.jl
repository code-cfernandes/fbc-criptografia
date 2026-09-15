"""
Não é bem um "ataque" — é a checagem de sanidade básica: encrypt seguido de
decrypt precisa devolver o texto original, em qualquer tamanho.
"""
struct AtaqueIdaEVolta <: Ataque
    tamanho_maximo::Int
end

AtaqueIdaEVolta(; tamanho_maximo::Integer = 130) = AtaqueIdaEVolta(Int(tamanho_maximo))

nome(::AtaqueIdaEVolta) = "Ida-e-volta (round trip)"

function executar(a::AtaqueIdaEVolta, alvo::AlvoCriptografico)
    falhas = Any[]
    for len in 0:(a.tamanho_maximo)
        texto = repeat("Q", len)
        try
            token = encrypt(alvo, texto)
            decifrado = decrypt(alvo, token)
            if decifrado != texto
                push!(falhas, len)
            end
        catch e
            push!(falhas, "$len (erro: $(sprint(showerror, e)))")
        end
    end

    if !isempty(falhas)
        amostra = join(falhas[1:min(10, length(falhas))], ", ")
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "Falhou em $(length(falhas)) tamanho(s): $amostra",
            Dict{String,Any}("falhas" => falhas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todos os $(a.tamanho_maximo + 1) tamanhos (0 a $(a.tamanho_maximo)) OK",
    )
end

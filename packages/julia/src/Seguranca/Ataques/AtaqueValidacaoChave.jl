"""
A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32 bytes
válida deve funcionar.
"""
struct AtaqueValidacaoChave <: Ataque
    tamanhos::Vector{Int}
end

AtaqueValidacaoChave(; tamanhos::AbstractVector{<:Integer} = [0, 1, 16, 31, 33, 64]) =
    AtaqueValidacaoChave(Int.(tamanhos))

nome(::AtaqueValidacaoChave) = "Validação do tamanho da chave"

function executar(a::AtaqueValidacaoChave, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de CriptografiaAlvo para trocar a chave."))
    end

    chave_original = chave_de_teste(alvo)
    aceitas_indevidamente = Int[]
    valida_rejeitada = false

    try
        for len in a.tamanhos
            CriptografiaAlvo(repeat("K", len))
            try
                encrypt(alvo, "x")
                push!(aceitas_indevidamente, len)
            catch
                # esperado
            end
        end

        CriptografiaAlvo(repeat("K", 32))
        try
            encrypt(alvo, "x")
        catch
            valida_rejeitada = true
        end
    finally
        ENV["FBC_KEY"] = chave_original
    end

    vulneravel = !isempty(aceitas_indevidamente) || valida_rejeitada

    detalhes = String[]
    if !isempty(aceitas_indevidamente)
        push!(
            detalhes,
            "chaves de tamanho inválido aceitas: " * join(aceitas_indevidamente, ", "),
        )
    end
    if valida_rejeitada
        push!(detalhes, "chave válida de 32 bytes foi rejeitada")
    end

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        vulneravel ? join(detalhes, "; ") :
        "Tamanhos inválidos rejeitados e chave de 32 bytes aceita",
    )
end

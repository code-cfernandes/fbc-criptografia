"""
Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as garantias de
confidencialidade (keystream reusado = "two-time pad"). Gera muitos tokens do
MESMO texto e verifica se os IVs nunca colidem.
"""
struct AtaqueColisaoIV <: Ataque
    geracoes::Int
end

AtaqueColisaoIV(; geracoes::Integer = 5000) = AtaqueColisaoIV(Int(geracoes))

nome(::AtaqueColisaoIV) = "Colisão de IV"

function executar(a::AtaqueColisaoIV, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_decode do alvo."))
    end

    vistos = Set{String}()
    colisoes = 0

    for _ in 1:(a.geracoes)
        token = encrypt(alvo, "MESMO_TEXTO_SEMPRE")
        decodificado = base64url_decode(alvo, token[4:end])
        iv = decompor(alvo, decodificado).iv
        chave_iv = bytes2hex(iv)
        if chave_iv in vistos
            colisoes += 1
        end
        push!(vistos, chave_iv)
    end

    if colisoes > 0
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "$colisoes colisão(ões) de IV em $(a.geracoes) gerações",
        )
    end

    return ResultadoAtaque(nome(a), false, "info", "0 colisões em $(a.geracoes) gerações")
end

"""
O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
ambíguo, um atacante pode reordenar/deslocar os campos e construir um
token que sistemas diferentes interpretam de formas diferentes. Todos os
rearranjos devem ser rejeitados pela integridade.
"""
struct AtaqueConfusaoCampos <: Ataque end

nome(::AtaqueConfusaoCampos) = "Confusão de campos do token (reordenação/deslocamento)"

function executar(a::AtaqueConfusaoCampos, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_encode/decode do alvo."))
    end

    texto = "MENSAGEM_PARA_TESTE_DE_CAMPOS"
    token = encrypt(alvo, texto)
    pref = prefixo(alvo)
    campos = decompor(alvo, base64url_decode(alvo, token[length(pref)+1:end]))

    integridade = campos.integridade
    ciphertext = campos.ciphertext
    iv = campos.iv

    x = UInt8[0x58] # 'X'

    variantes = Pair{String,Vector{UInt8}}[
        "iv no início" => vcat(iv, integridade, ciphertext),
        "ciphertext antes da integridade" => vcat(ciphertext, integridade, iv),
        "iv duplicado no fim" => vcat(integridade, ciphertext, iv, iv),
        "integridade encurtada" => vcat(integridade[2:end], ciphertext, iv),
        "byte extra no início" => vcat(x, integridade, ciphertext, iv),
        "byte extra entre integridade e ciphertext" =>
            vcat(integridade, x, ciphertext, iv),
        "byte extra antes do iv" => vcat(integridade, ciphertext, x, iv),
        "iv rotacionado" => vcat(integridade, ciphertext, reverse(iv)),
        "iv e último byte do ciphertext trocados" =>
            vcat(integridade, ciphertext[1:end-1], iv, ciphertext[end:end]),
    ]

    aceitas = String[]
    for (nome_variante, bruto) in variantes
        token_variante = pref * base64url_encode(alvo, bruto)
        try
            r = decrypt(alvo, token_variante)
            push!(
                aceitas,
                "$nome_variante -> aceito (retornou $(length(codeunits(r))) bytes)",
            )
        catch
            # esperado
        end
    end

    if !isempty(aceitas)
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "$(length(aceitas)) rearranjo(s) de campo foram aceitos",
            Dict{String,Any}("exemplos" => aceitas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todos os $(length(variantes)) rearranjos de campo foram rejeitados",
    )
end

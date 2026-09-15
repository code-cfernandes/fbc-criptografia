"""
Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar (força
bruta de 1 byte) valores para ver se algum token adulterado é aceito. Com um
MAC de 32 bytes, nenhuma tentativa deveria passar.
"""
struct AtaqueMac <: Ataque
    mensagem::String
end

AtaqueMac(; mensagem::AbstractString = "mensagem para o ataque de MAC") =
    AtaqueMac(String(mensagem))

nome(::AtaqueMac) = "Força bruta e truncamento do MAC"

function executar(a::AtaqueMac, alvo::AlvoCriptografico)
    pref = prefixo(alvo)
    token = encrypt(alvo, a.mensagem)
    decodificado = base64url_decode(alvo, token[length(pref)+1:end])
    campos = decompor(alvo, decodificado)

    montar(integridade) = pref * base64url_encode(
        alvo,
        recompor(alvo, (integridade=integridade, ciphertext=campos.ciphertext, iv=campos.iv)),
    )

    aceitos = String[]

    # 1) integridade zerada
    try
        decrypt(alvo, montar(zeros(UInt8, length(campos.integridade))))
        push!(aceitos, "integridade zerada")
    catch
        # esperado
    end

    # 2) integridade truncada pela metade
    try
        decrypt(alvo, montar(campos.integridade[1:16]))
        push!(aceitos, "integridade truncada (16 bytes)")
    catch
        # esperado
    end

    # 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
    # que reconstruiria o próprio token válido e não é uma forja)
    base = copy(campos.integridade)
    for v in 0:255
        if v == base[1]
            continue
        end
        tentativa = copy(base)
        tentativa[1] = UInt8(v)
        try
            decrypt(alvo, montar(tentativa))
            push!(aceitos, "byte 0 do MAC = $v")
        catch
            # esperado
        end
    end

    vulneravel = !isempty(aceitos)

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        vulneravel ?
        "$(length(aceitos)) variante(s) de MAC aceitas: $(join(aceitos[1:min(5, length(aceitos))], "; "))" :
        "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita",
        Dict{String,Any}("aceitos" => aceitos),
    )
end

"""
O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
token (ciphertext, iv, ou o campo de integridade) ainda decifra "com sucesso",
a cifra não está autenticando o conteúdo.
"""
struct AtaqueAdulteracao <: Ataque
    tentativas::Int
end

AtaqueAdulteracao(; tentativas::Integer = 500) = AtaqueAdulteracao(Int(tentativas))

nome(::AtaqueAdulteracao) = "Adulteração de bits (integridade)"

function executar(a::AtaqueAdulteracao, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_encode/decode do alvo."))
    end

    aceitos = String[]

    for t in 0:(a.tentativas-1)
        texto = "MSG_$t" * repeat("X", random_int(0, 50))
        token = encrypt(alvo, texto)
        decodificado = base64url_decode(alvo, token[4:end])
        campos = decompor(alvo, decodificado)

        nome_campo = array_rand_key(campos)
        valor = copy(campos[nome_campo])
        isempty(valor) && continue
        pos = random_int(1, length(valor))
        valor[pos] = valor[pos] ⊻ UInt8(1 << random_int(0, 7))
        campos = merge(campos, NamedTuple{(nome_campo,)}((valor,)))

        token_adulterado = prefixo(alvo) * base64url_encode(alvo, recompor(alvo, campos))

        try
            resultado = decrypt(alvo, token_adulterado)
            push!(
                aceitos,
                "campo=$nome_campo, texto original=$texto, resultado aceito=$resultado",
            )
        catch
            # esperado — a adulteração deveria ser rejeitada
        end
    end

    if !isempty(aceitos)
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "$(length(aceitos)) de $(a.tentativas) tokens adulterados foram ACEITOS",
            Dict{String,Any}("exemplos" => aceitos[1:min(5, length(aceitos))]),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todas as $(a.tentativas) adulterações foram rejeitadas",
    )
end

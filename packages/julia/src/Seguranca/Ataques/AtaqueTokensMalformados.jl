"""
Robustez do parser de tokens: qualquer entrada que não seja um token íntegro e
bem formado DEVE ser rejeitada com exceção. Um decrypt() que devolve lixo em
vez de lançar (ou que aceita truncamentos/bytes extras) é uma porta pra bugs de
validação e "token smuggling".
"""
struct AtaqueTokensMalformados <: Ataque end

nome(::AtaqueTokensMalformados) = "Tokens malformados (fuzzing de entrada)"

function executar(a::AtaqueTokensMalformados, alvo::AlvoCriptografico)
    token = encrypt(alvo, "MENSAGEM_VALIDA_PARA_TESTE")
    pref = prefixo(alvo)
    corpo = token[length(pref)+1:end]

    casos = Pair{String,String}[
        "vazio" => "",
        "só prefixo" => pref,
        "prefixo errado" => "XXX" * corpo,
        "base64 inválido" => pref * "!!!@@@###",
        "bytes extras no fim" => token * "AAAA",
        "bytes extras no início" => "AAAA" * token,
    ]
    for len in 1:(length(token)-1)
        push!(casos, "truncado em $len" => token[1:len])
    end
    for i in 0:19
        push!(casos, "lixo aleatório $i" => pref * bytes2hex(random_bytes(16)))
    end

    aceitos = String[]
    for (nome_caso, t) in casos
        try
            r = decrypt(alvo, t)
            push!(aceitos, "$nome_caso -> aceito (retornou $(length(codeunits(r))) bytes)")
        catch
            # comportamento esperado
        end
    end

    if !isempty(aceitos)
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "$(length(aceitos)) entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas",
            Dict{String,Any}("exemplos" => aceitos[1:min(10, length(aceitos))]),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todas as $(length(casos)) entradas malformadas foram rejeitadas",
    )
end

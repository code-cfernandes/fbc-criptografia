"""
Um mesmo token não deveria ter múltiplas representações textuais válidas.
Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
token. Isso é "token smuggling": sistemas que comparam/usam a string do
token de formas diferentes (cache, WAF, deduplicação/replay) discordam
sobre o que ele significa.
"""
struct AtaqueCanonicalizacaoToken <: Ataque end

nome(::AtaqueCanonicalizacaoToken) = "Canonicalização do token (base64 não-canônico)"

function executar(a::AtaqueCanonicalizacaoToken, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_encode/decode do alvo."))
    end

    texto = "MENSAGEM_DE_TESTE_DE_CANONICALIZACAO"
    token = encrypt(alvo, texto)
    pref = prefixo(alvo)
    corpo = token[length(pref)+1:end]
    meio = trunc(Int, length(corpo) / 2)

    variantes = Pair{String,String}[]
    for p in [0, meio, length(corpo)-1]
        push!(variantes, "espaço na posição $p" => pref * corpo[1:p] * " " * corpo[p+1:end])
        push!(variantes, "newline na posição $p" => pref * corpo[1:p] * "\n" * corpo[p+1:end])
        push!(variantes, "tab na posição $p" => pref * corpo[1:p] * "\t" * corpo[p+1:end])
    end
    push!(
        variantes,
        "alfabeto padrão (+/)" => pref * replace(replace(corpo, "-" => "+"), "_" => "/"),
    )
    push!(variantes, "padding \"=\" extra" => pref * corpo * "=")
    push!(
        variantes,
        "caractere inválido no meio" => pref * corpo[1:meio] * "!" * corpo[meio+1:end],
    )

    aceitas = String[]
    for (nome_variante, v) in variantes
        v == token && continue
        try
            if decrypt(alvo, v) == texto
                push!(aceitas, nome_variante)
            end
        catch
            # esperado
        end
    end

    if !isempty(aceitas)
        return ResultadoAtaque(
            nome(a),
            true,
            "media",
            "$(length(aceitas)) variante(s) textualmente diferente(s) decifram para o mesmo texto: $(join(aceitas, "; "))",
            Dict{String,Any}("variantes_aceitas" => aceitas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todas as $(length(variantes)) variantes não-canônicas foram rejeitadas",
    )
end

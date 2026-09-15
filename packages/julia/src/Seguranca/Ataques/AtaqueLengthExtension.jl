"""
Length extension / truncamento: a estrutura do token é
integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
Truncar, estender ou deslocar bytes não pode produzir um token aceito.
"""
struct AtaqueLengthExtension <: Ataque
    mensagem::String
end

AtaqueLengthExtension(; mensagem::AbstractString = "texto para o ataque de length extension") =
    AtaqueLengthExtension(String(mensagem))

nome(::AtaqueLengthExtension) = "Length extension / truncamento de token"

function executar(a::AtaqueLengthExtension, alvo::AlvoCriptografico)
    pref = prefixo(alvo)
    token = encrypt(alvo, a.mensagem)
    corpo = token[length(pref)+1:end]
    meio = div(length(corpo), 2)

    variantes = Pair{String,String}[
        "append A" => pref * corpo * "A",
        "append =" => pref * corpo * "=",
        "truncar 1 char" => pref * corpo[1:end-1],
        "truncar 2 chars" => pref * corpo[1:end-2],
        "inserir ! no meio" => pref * corpo[1:meio] * "!" * corpo[meio+1:end],
        "prefixo extra" => pref * "A" * corpo,
    ]

    # variantes que mexem nos campos decodificados
    try
        decoded = base64url_decode(alvo, corpo)
        campos = decompor(alvo, decoded)

        ct_maior = vcat(campos.ciphertext, UInt8[0x41])
        push!(
            variantes,
            "ciphertext +1 byte" => pref * base64url_encode(
                alvo,
                recompor(alvo, (integridade=campos.integridade, ciphertext=ct_maior, iv=campos.iv)),
            ),
        )

        ct_menor = campos.ciphertext[1:max(0, length(campos.ciphertext)-1)]
        push!(
            variantes,
            "ciphertext -1 byte" => pref * base64url_encode(
                alvo,
                recompor(alvo, (integridade=campos.integridade, ciphertext=ct_menor, iv=campos.iv)),
            ),
        )

        iv_maior = vcat(campos.iv, UInt8[0x42])
        push!(
            variantes,
            "iv +1 byte" => pref * base64url_encode(
                alvo,
                recompor(alvo, (integridade=campos.integridade, ciphertext=campos.ciphertext, iv=iv_maior)),
            ),
        )
    catch
        # se a decodificação falhar, segue com as variantes textuais
    end

    aceitas = String[]
    for (nome_variante, v) in variantes
        v == token && continue
        try
            decrypt(alvo, v)
            push!(aceitas, nome_variante)
        catch
            # esperado
        end
    end

    vulneravel = !isempty(aceitas)

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        vulneravel ?
        "$(length(aceitas)) variante(s) aceita(s): $(join(aceitas, "; "))" :
        "Todas as $(length(variantes)) variantes de truncamento/extensão foram rejeitadas",
        Dict{String,Any}("aceitas" => aceitas),
    )
end

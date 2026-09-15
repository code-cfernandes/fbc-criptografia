"""
Garante que um token só decifra com a chave correta: com qualquer outra chave de
32 bytes, decrypt() tem que lançar.

Cuidado: CriptografiaAlvo escreve a chave no ambiente do processo; a chave
original é restaurada no final pra não afetar os outros ataques.
"""
struct AtaqueChaveErrada <: Ataque
    tentativas::Int
end

AtaqueChaveErrada(; tentativas::Integer = 30) = AtaqueChaveErrada(Int(tentativas))

nome(::AtaqueChaveErrada) = "Rejeição de chave incorreta"

function executar(a::AtaqueChaveErrada, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de CriptografiaAlvo para trocar a chave."))
    end

    chave_original = chave_de_teste(alvo)
    tokens = [encrypt(alvo, "MENSAGEM_SECRETA_$i") for i in 0:(a.tentativas-1)]

    aceitos = String[]
    try
        for (i, token) in enumerate(tokens)
            CriptografiaAlvo(bytes2hex(random_bytes(16)))
            try
                r = decrypt(alvo, token)
                push!(aceitos, "tentativa $(i-1) aceitou (retornou $r)")
            catch
                # esperado
            end
        end
    finally
        ENV["FBC_KEY"] = chave_original
    end

    if !isempty(aceitos)
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "$(length(aceitos)) de $(a.tentativas) tokens foram aceitos com a chave errada",
            Dict{String,Any}("exemplos" => aceitos[1:min(5, length(aceitos))]),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Nenhum dos $(a.tentativas) tokens foi aceito com chave incorreta",
    )
end

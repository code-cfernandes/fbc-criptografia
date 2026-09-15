"""
Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o resto
do gerador não reintroduzir key/iv separadamente, vale exatamente:

    keystream(key, iv) == keystream(key ^ d, iv ^ d)

para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
propriedade estrutural relevante: significa que key e iv não entram de forma
independente na cifra, o que enfraquece o modelo de segurança (o IV deveria
contribuir com entropia própria, não só deslocar a chave por XOR).
"""
struct AtaqueSeparacaoChaveIV <: Ataque
    tentativas::Int
    tamanho_bloco::Int
end

AtaqueSeparacaoChaveIV(; tentativas::Integer = 50, tamanho_bloco::Integer = 32) =
    AtaqueSeparacaoChaveIV(Int(tentativas), Int(tamanho_bloco))

nome(::AtaqueSeparacaoChaveIV) = "Separação chave/IV (invariância a key XOR iv)"

function executar(a::AtaqueSeparacaoChaveIV, alvo::AlvoCriptografico)
    tam_chave = length(codeunits(chave_de_teste(alvo)))
    tam_iv = tamanho_iv(alvo)

    confirmacoes = 0
    for _ in 1:(a.tentativas)
        chave = random_bytes(tam_chave)
        iv = random_bytes(tam_iv)
        d = random_bytes(tam_iv)

        chave2 = Vector{UInt8}(undef, tam_chave)
        for p in 0:(tam_chave-1)
            chave2[p+1] = chave[p+1] ⊻ d[mod(p, tam_iv)+1]
        end
        iv2 = Vector{UInt8}(undef, tam_iv)
        for p in 0:(tam_iv-1)
            iv2[p+1] = iv[p+1] ⊻ d[p+1]
        end

        ks1 = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho_bloco)
        ks2 = gerar_keystream_bruto(alvo, chave2, iv2, "enc", a.tamanho_bloco)

        if ks1 == ks2
            confirmacoes += 1
        end
    end

    invariante = confirmacoes == a.tentativas

    return ResultadoAtaque(
        nome(a),
        invariante,
        invariante ? "media" : "info",
        invariante ?
        "Confirmado em $(a.tentativas)/$(a.tentativas): keystream(key,iv) == keystream(key^d, iv^d). " *
        "O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule." :
        "Invariância não se confirmou ($confirmacoes/$(a.tentativas)); key e iv entram de forma independente.",
        Dict{String,Any}("confirmacoes" => confirmacoes, "tentativas" => a.tentativas),
    )
end

"""
Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
`keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
byte e também coincidência direta do keystream.
"""
struct AtaqueRotacional <: Ataque
    tamanho::Int
end

AtaqueRotacional(; tamanho::Integer = 64) = AtaqueRotacional(Int(tamanho))

nome(::AtaqueRotacional) = "Rotacional/slide (simetria por rotação)"

function _rotacionar(buf::AbstractVector{UInt8}, k::Integer)
    n = length(buf)
    out = Vector{UInt8}(undef, n)
    for i in 0:(n-1)
        out[i+1] = buf[mod(i + k, n)+1]
    end
    return out
end

function executar(a::AtaqueRotacional, alvo::AlvoCriptografico)
    chave = to_buffer(chave_de_teste(alvo))
    iv = random_bytes(tamanho_iv(alvo))
    ks1 = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho)

    coincidencias = String[]
    for k in 1:(length(chave)-1)
        ks2 = gerar_keystream_bruto(
            alvo,
            _rotacionar(chave, k),
            _rotacionar(iv, k),
            "enc",
            a.tamanho,
        )

        if ks2 == ks1
            push!(coincidencias, "rotação $k: keystream idêntico")
            continue
        end
        # metade inicial de ks1 rotacionada deve bater com ks2 se houver simetria
        alvo_rot = _rotacionar(ks1[1:32], k)
        if ks2[1:32] == alvo_rot
            push!(coincidencias, "rotação $k: keystream rotacionado")
        end
    end

    vulneravel = !isempty(coincidencias)

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        vulneravel ?
        "Simetria rotacional encontrada: $(join(coincidencias[1:min(5, length(coincidencias))], "; "))" :
        "Nenhuma das $(length(chave) - 1) rotações de byte reproduziu o keystream",
        Dict{String,Any}("coincidencias" => coincidencias),
    )
end

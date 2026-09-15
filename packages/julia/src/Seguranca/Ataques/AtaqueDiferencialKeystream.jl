"""
Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
boa, essas diferenças são uniformes e únicas. Sinaliza:
 - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
 - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
   que é o insumo básico de um ataque diferencial.
"""
struct AtaqueDiferencialKeystream <: Ataque
    amostras::Int
    tamanho_bloco::Int
end

AtaqueDiferencialKeystream(; amostras::Integer = 2000, tamanho_bloco::Integer = 32) =
    AtaqueDiferencialKeystream(Int(amostras), Int(tamanho_bloco))

nome(::AtaqueDiferencialKeystream) = "Diferencial do keystream (delta fixo no IV)"

function _xor_buffers(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})
    return UInt8[a[i] ⊻ b[i] for i in eachindex(a)]
end

function executar(a::AtaqueDiferencialKeystream, alvo::AlvoCriptografico)
    chave = random_bytes(length(chave_de_teste(alvo)))
    tam_iv = tamanho_iv(alvo)

    delta = zeros(UInt8, tam_iv)
    delta[random_int(0, tam_iv-1)+1] = UInt8(1 << random_int(0, 7))

    total_bits = a.tamanho_bloco * 8
    sempre_zero = trues(total_bits)
    sempre_um = trues(total_bits)
    deltas = Set{String}()

    for _ in 1:(a.amostras)
        iv = random_bytes(tam_iv)
        iv2 = _xor_buffers(iv, delta)

        ks1 = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho_bloco)
        ks2 = gerar_keystream_bruto(alvo, chave, iv2, "enc", a.tamanho_bloco)
        d = _xor_buffers(ks1, ks2)
        push!(deltas, bytes2hex(d))

        for p in 0:(length(d)-1)
            byte = d[p+1]
            for b in 0:7
                idx = p * 8 + b
                if ((byte >> b) & 1) == 1
                    sempre_zero[idx+1] = false
                else
                    sempre_um[idx+1] = false
                end
            end
        end
    end

    bits_fixos = 0
    for idx in 1:total_bits
        if sempre_zero[idx] || sempre_um[idx]
            bits_fixos += 1
        end
    end
    colisoes = a.amostras - length(deltas)

    vulneravel = bits_fixos > 0 || colisoes > 0

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "delta de 1 bit no IV: $bits_fixos bit(s) de saída fixo(s), $colisoes diferencial(is) repetido(s) em $(a.amostras) amostras",
        Dict{String,Any}("bits_fixos" => bits_fixos, "colisoes" => colisoes),
    )
end

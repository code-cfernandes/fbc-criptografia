"""
SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar esse
bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior bit de
saída; se algum fica longe de 50%, a difusão tem ponto cego.
"""
struct AtaqueSAC <: Ataque
    tamanho_bloco::Int
    amostras::Int
    tolerancia::Float64
end

AtaqueSAC(;
    tamanho_bloco::Integer = 32,
    amostras::Integer = 40,
    tolerancia::Real = 0.05,
) = AtaqueSAC(Int(tamanho_bloco), Int(amostras), Float64(tolerancia))

nome(::AtaqueSAC) = "SAC (Strict Avalanche Criterion)"

function executar(a::AtaqueSAC, alvo::AlvoCriptografico)
    chave = to_buffer(chave_de_teste(alvo))
    total_bits = a.tamanho_bloco * 8
    flips = zeros(Int, total_bits)
    tam_iv = tamanho_iv(alvo)
    total = 0

    for pos in 0:(tam_iv-1)
        for bit in 0:7
            for _ in 1:(a.amostras)
                iv1 = random_bytes(tam_iv)
                iv2 = copy(iv1)
                iv2[pos+1] = iv2[pos+1] ⊻ UInt8(1 << bit)

                ks1 = gerar_keystream_bruto(alvo, chave, iv1, "enc", a.tamanho_bloco)
                ks2 = gerar_keystream_bruto(alvo, chave, iv2, "enc", a.tamanho_bloco)

                for j in 0:(total_bits-1)
                    b1 = (ks1[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
                    b2 = (ks2[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
                    if b1 != b2
                        flips[j+1] += 1
                    end
                end
                total += 1
            end
        end
    end

    pior = -1
    pior_desvio = 0.0
    pior_p = 0.5
    for j in 0:(total_bits-1)
        p = flips[j+1] / total
        desvio = abs(p - 0.5)
        if desvio > pior_desvio
            pior_desvio = desvio
            pior = j
            pior_p = p
        end
    end

    vulneravel = pior_desvio > a.tolerancia

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "pior bit de saída=$pior: p=$(fmt(pior_p * 100, 2))% (esperado 50%, tolerância ±$(fmt(a.tolerancia * 100, 1))%); $total amostras por bit de entrada",
        Dict{String,Any}("pior" => pior, "pior_p" => pior_p, "desvio" => pior_desvio),
    )
end

"""
BIC (Bit Independence Criterion): pares de bits de saída não devem estar
correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV e
registra quais bits de saída mudaram; depois mede a correlação (phi) entre cada
par de bits de saída. Pares muito correlacionados indicam difusão acoplada (um
bit "carrega" informação sobre outro).
"""
struct AtaqueBIC <: Ataque
    tamanho_bloco::Int
    amostras::Int
    limite::Float64
end

AtaqueBIC(; tamanho_bloco::Integer = 32, amostras::Integer = 300, limite::Real = 0.35) =
    AtaqueBIC(Int(tamanho_bloco), Int(amostras), Float64(limite))

nome(::AtaqueBIC) = "BIC (Bit Independence Criterion)"

function executar(a::AtaqueBIC, alvo::AlvoCriptografico)
    chave = to_buffer(chave_de_teste(alvo))
    total_bits = a.tamanho_bloco * 8
    tam_iv = tamanho_iv(alvo)

    amostras_flips = zeros(Int, a.amostras, total_bits)
    for s in 1:(a.amostras)
        iv1 = random_bytes(tam_iv)
        iv2 = copy(iv1)
        pos = random_int(0, tam_iv - 1)
        iv2[pos+1] = iv2[pos+1] ⊻ UInt8(1 << random_int(0, 7))

        ks1 = gerar_keystream_bruto(alvo, chave, iv1, "enc", a.tamanho_bloco)
        ks2 = gerar_keystream_bruto(alvo, chave, iv2, "enc", a.tamanho_bloco)

        for j in 0:(total_bits-1)
            b1 = (ks1[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
            b2 = (ks2[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
            amostras_flips[s, j+1] = b1 != b2 ? 1 : 0
        end
    end

    pior_phi = 0.0
    pior_par = (-1, -1)
    n = a.amostras

    for x in 0:(total_bits-1)
        for y in (x+1):(total_bits-1)
            n11 = 0
            n10 = 0
            n01 = 0
            n00 = 0
            for s in 1:n
                fa = amostras_flips[s, x+1]
                fb = amostras_flips[s, y+1]
                if fa == 1 && fb == 1
                    n11 += 1
                elseif fa == 1 && fb == 0
                    n10 += 1
                elseif fa == 0 && fb == 1
                    n01 += 1
                else
                    n00 += 1
                end
            end
            den = sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
            phi = den > 0 ? (n11 * n00 - n10 * n01) / den : 0.0
            if abs(phi) > abs(pior_phi)
                pior_phi = phi
                pior_par = (x, y)
            end
        end
    end

    vulneravel = abs(pior_phi) > a.limite

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "maior |phi|=$(fmt(abs(pior_phi), 3)) entre bits de saída [$(pior_par[1]), $(pior_par[2])] (limite $(a.limite)); $n amostras",
        Dict{String,Any}("pior_phi" => pior_phi, "par" => [pior_par[1], pior_par[2]]),
    )
end

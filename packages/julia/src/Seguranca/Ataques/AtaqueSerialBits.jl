"""
Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
"""
struct AtaqueSerialBits <: Ataque
    tamanho::Int
    ordens::Vector{Int}
end

AtaqueSerialBits(; tamanho::Integer = 4096, ordens::Vector{<:Integer} = [2, 3, 4]) =
    AtaqueSerialBits(Int(tamanho), Int.(ordens))

nome(::AtaqueSerialBits) = "Teste serial (padrões de bits sobrepostos)"

function executar(a::AtaqueSerialBits, alvo::AlvoCriptografico)
    ks = gerar_keystream_bruto(
        alvo,
        chave_de_teste(alvo),
        random_bytes(tamanho_iv(alvo)),
        "enc",
        a.tamanho,
    )

    bits = bits_msb(ks)
    n = length(bits)

    problemas = String[]
    dados = Dict{String,Any}()

    for m in a.ordens
        total = 1 << m
        contagem = zeros(Int, total)
        janelas = n - m + 1

        for i in 0:(janelas-1)
            v = 0
            for j in 0:(m-1)
                v = (v << 1) | bits[i+j+1]
            end
            contagem[v+1] += 1
        end

        esperado = janelas / total
        chi2 = 0.0
        for c in contagem
            chi2 += (c - esperado)^2 / esperado
        end
        dof = total - 1
        # Wilson-Hilferty: aproxima chi² por normal de forma bem mais precisa
        # para dof pequeno.
        z = ((chi2 / dof)^(1 / 3) - (1 - 2 / (9 * dof))) / sqrt(2 / (9 * dof))
        dados["m$m"] = Dict{String,Any}("chi2" => chi2, "z" => z)

        if z > 6.0
            push!(problemas, "m=$m chi2=$(fmt(chi2, 1)) (z=$(fmt(z, 1)))")
        end
    end

    if !isempty(problemas)
        return ResultadoAtaque(nome(a), true, "media", join(problemas, "; "), dados)
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Padrões sobrepostos de 2/3/4 bits com frequência uniforme",
        dados,
    )
end

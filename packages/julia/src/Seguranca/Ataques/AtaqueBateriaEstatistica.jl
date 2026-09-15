"""
Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
global (monobit), frequência por posição de bit, teste de runs e frequência
por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.

Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
pra não depender de funções numéricas especiais.
"""
struct AtaqueBateriaEstatistica <: Ataque
    tamanho::Int
    z_limite::Float64
end

AtaqueBateriaEstatistica(; tamanho::Integer = 16384, z_limite::Real = 4.0) =
    AtaqueBateriaEstatistica(Int(tamanho), Float64(z_limite))

nome(::AtaqueBateriaEstatistica) = "Bateria estatística de bits (monobit/runs/blocos)"

function _bits_msb(bytes::AbstractVector{UInt8})
    bits = Int[]
    for byte in bytes
        for b in 7:-1:0
            push!(bits, Int((byte >> b) & 0x01))
        end
    end
    return bits
end

function executar(a::AtaqueBateriaEstatistica, alvo::AlvoCriptografico)
    ks = gerar_keystream_bruto(
        alvo,
        chave_de_teste(alvo),
        random_bytes(tamanho_iv(alvo)),
        "enc",
        a.tamanho,
    )

    bits = _bits_msb(ks)
    n = length(bits)
    problemas = String[]
    dados = Dict{String,Any}()

    # 1) Monobit: soma +1/-1
    soma = 0
    for b in bits
        soma += b == 1 ? 1 : -1
    end
    z_monobit = abs(soma) / sqrt(n)
    dados["monobit_z"] = z_monobit
    if z_monobit > a.z_limite
        push!(problemas, "monobit z=$(fmt(z_monobit, 2))")
    end

    # 2) Frequência por posição de bit
    uns_por_pos = zeros(Int, 8)
    conta_por_pos = zeros(Int, 8)
    for byte in ks
        for b in 0:7
            if ((byte >> b) & 1) == 1
                uns_por_pos[b+1] += 1
            end
            conta_por_pos[b+1] += 1
        end
    end
    pos_viesadas = Dict{Int,Float64}()
    for b in 0:7
        frac = uns_por_pos[b+1] / conta_por_pos[b+1]
        z = abs(frac - 0.5) / (0.5 / sqrt(conta_por_pos[b+1]))
        if z > a.z_limite
            pos_viesadas[b] = frac
        end
    end
    dados["bit_posicao_viesadas"] = pos_viesadas
    if !isempty(pos_viesadas)
        push!(
            problemas,
            "viés por posição de bit: " * join(sort(collect(keys(pos_viesadas))), ", "),
        )
    end

    # 3) Runs test
    pi = sum(bits) / n
    if abs(pi - 0.5) < 2 / sqrt(n)
        runs = 1
        for i in 2:n
            if bits[i] != bits[i-1]
                runs += 1
            end
        end
        esperado = 2 * n * pi * (1 - pi)
        desvio = 2 * sqrt(2 * n) * pi * (1 - pi)
        z_runs = abs(runs - esperado) / desvio
        dados["runs_z"] = z_runs
        if z_runs > a.z_limite
            push!(problemas, "runs z=$(fmt(z_runs, 2))")
        end
    end

    # 4) Frequência por bloco (M = 128 bits)
    m = 128
    num_blocos = trunc(Int, n / m)
    if num_blocos > 0
        chi = 0.0
        for i in 0:(num_blocos-1)
            uns = 0
            for j in 0:(m-1)
                uns += bits[i*m+j+1]
            end
            chi += (uns / m - 0.5)^2
        end
        chi *= 4 * m
        z_blocos = (chi - num_blocos) / sqrt(2 * num_blocos)
        dados["blocos_chi2"] = chi
        dados["blocos_z"] = z_blocos
        if z_blocos > a.z_limite
            push!(problemas, "frequência por bloco chi2=$(fmt(chi, 1))")
        end
    end

    if !isempty(problemas)
        return ResultadoAtaque(nome(a), true, "media", join(problemas, "; "), dados)
    end

    runs_z = get(dados, "runs_z", 0.0)
    blocos_chi2 = get(dados, "blocos_chi2", 0.0)

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "monobit z=$(fmt(z_monobit, 2)), runs z=$(fmt(runs_z, 2)), blocos chi2=$(fmt(blocos_chi2, 1)) - todos abaixo do limite z=$(fmt(a.z_limite, 0))",
        dados,
    )
end

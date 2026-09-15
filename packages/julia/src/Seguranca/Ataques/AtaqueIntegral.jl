"""
Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de um
byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.

Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta, a
saída como função do byte variado fica "quase bijetiva" e a soma tende a zero
MUITO mais que o acaso - um distinguisher clássico.

Como uma única (chave, IV) tem variância alta, acumula várias tentativas para
estimar o viés de forma estável (comparado a p=1/256).
"""
struct AtaqueIntegral <: Ataque
    tamanho_bloco::Int
    posicoes_iv::Int
    posicoes_chave::Int
    tentativas::Int
    limite_z::Float64
end

AtaqueIntegral(;
    tamanho_bloco::Integer = 32,
    posicoes_iv::Integer = 8,
    posicoes_chave::Integer = 8,
    tentativas::Integer = 16,
    limite_z::Real = 5.0,
) = AtaqueIntegral(
    Int(tamanho_bloco),
    Int(posicoes_iv),
    Int(posicoes_chave),
    Int(tentativas),
    Float64(limite_z),
)

nome(::AtaqueIntegral) = "Integral (soma balanceada variando 1 byte de IV/chave)"

function _integral_somar_variando(alvo, chave, iv_base, campo::Symbol, pos, tamanho_bloco)
    xor = zeros(UInt8, tamanho_bloco)
    for v in 0:255
        k = copy(chave)
        iv = copy(iv_base)
        if campo === :iv
            iv[pos+1] = UInt8(v)
        else
            k[pos+1] = UInt8(v)
        end
        ks = gerar_keystream_bruto(alvo, k, iv, "enc", tamanho_bloco)
        xor = xor_bytes(xor, ks)
    end
    zeros_qtd = count(==(0x00), xor)
    return xor, zeros_qtd
end

function executar(a::AtaqueIntegral, alvo::AlvoCriptografico)
    tam_iv = tamanho_iv(alvo)
    tam_chave = length(codeunits(chave_de_teste(alvo)))

    distinguidores = String[]
    zeros_total = 0
    bytes_total = 0

    for _ in 1:(a.tentativas)
        chave = random_bytes(tam_chave)
        iv_base = random_bytes(tam_iv)

        for pos in 0:(min(a.posicoes_iv, tam_iv)-1)
            xor, z = _integral_somar_variando(alvo, chave, iv_base, :iv, pos, a.tamanho_bloco)
            zeros_total += z
            bytes_total += a.tamanho_bloco
            if all(==(0x00), xor)
                push!(distinguidores, "iv[$pos]")
            end
        end

        for pos in 0:(min(a.posicoes_chave, tam_chave)-1)
            xor, z = _integral_somar_variando(alvo, chave, iv_base, :key, pos, a.tamanho_bloco)
            zeros_total += z
            bytes_total += a.tamanho_bloco
            if all(==(0x00), xor)
                push!(distinguidores, "key[$pos]")
            end
        end
    end

    p = 1 / 256
    esperado = bytes_total * p
    desvio = sqrt(bytes_total * p * (1 - p))
    z = desvio > 0 ? (zeros_total - esperado) / desvio : 0.0

    vulneravel = !isempty(distinguidores) || z > a.limite_z

    if !isempty(distinguidores)
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "Soma balanceada (XOR zero) encontrada variando: " *
            join(distinguidores[1:min(10, length(distinguidores))], ", "),
            Dict{String,Any}("distinguidores" => distinguidores),
        )
    end

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        "bytes de saída zerados=$zeros_total (esperado ~$(fmt(esperado, 1)), z=$(fmt(z, 2))) em $bytes_total amostras; limite z=$(fmt(a.limite_z, 1))",
        Dict{String,Any}("zeros" => zeros_total, "esperado" => esperado, "z" => z),
    )
end

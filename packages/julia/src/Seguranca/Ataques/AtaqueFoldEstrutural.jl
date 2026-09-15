"""
Esse é o ataque que pegou o bug mais sério que encontramos: quando a
distância de mistura era exatamente metade do bloco, TODOS os IVs
aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
"""
struct AtaqueFoldEstrutural <: Ataque
    amostras::Int
    tamanho_bloco::Int
end

AtaqueFoldEstrutural(; amostras::Integer = 5000, tamanho_bloco::Integer = 32) =
    AtaqueFoldEstrutural(Int(amostras), Int(tamanho_bloco))

nome(::AtaqueFoldEstrutural) = "Fold estrutural (metades/quartos/oitavos repetidos)"

function executar(a::AtaqueFoldEstrutural, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)

    divisores = [
        d for d in [2, 4, 8, 16] if a.tamanho_bloco % d == 0 && div(a.tamanho_bloco, d) >= 1
    ]
    ocorrencias = Dict{Int,Int}(d => 0 for d in divisores)

    # Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
    # a chance de colisão por acaso é ~1/256^tam por par comparado -
    # desprezível para tam >= 2, então qualquer contagem > 0 já é
    # suspeita o bastante pra investigar (ajustamos a margem pra
    # fatias de 1-2 bytes, onde colisão por acaso é mais provável).
    for _ in 1:(a.amostras)
        ks = gerar_keystream_bruto(
            alvo,
            chave,
            random_bytes(tamanho_iv(alvo)),
            "enc",
            a.tamanho_bloco,
        )
        for divisor in divisores
            tam_fatia = div(a.tamanho_bloco, divisor)
            primeira_fatia = ks[1:tam_fatia]
            for j in 1:(divisor-1)
                if ks[j*tam_fatia+1:(j+1)*tam_fatia] == primeira_fatia
                    ocorrencias[divisor] += 1
                    break
                end
            end
        end
    end

    margem(divisor::Integer) =
        div(a.tamanho_bloco, divisor) <= 2 ? trunc(Int, a.amostras * 0.01) + 3 : 5

    problemas = Dict{Int,Int}()
    for divisor in divisores
        c = ocorrencias[divisor]
        if c > margem(divisor)
            problemas[divisor] = c
        end
    end

    if !isempty(problemas)
        detalhe = join(
            [
                "1/$d do bloco repetido em $(problemas[d])/$(a.amostras)"
                for d in divisores if haskey(problemas, d)
            ],
            ", ",
        )
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            detalhe,
            Dict{String,Any}("ocorrencias" => ocorrencias),
        )
    end

    json_ocorrencias =
        "{" * join(["\"$d\":$(ocorrencias[d])" for d in divisores], ",") * "}"

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Nenhuma repetição estrutural acima do ruído esperado: " * json_ocorrencias,
    )
end

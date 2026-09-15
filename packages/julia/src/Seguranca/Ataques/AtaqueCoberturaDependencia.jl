"""
Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
pra evitar falso-positivo por coincidência de valor). Uma dependência
ausente indica que a mistura não se propagou completamente - um atacante
poderia isolar e atacar aquele par de posições separadamente do resto.
"""
struct AtaqueCoberturaDependencia <: Ataque
    tamanho_bloco::Int
    perturbacoes_por_par::Int
end

AtaqueCoberturaDependencia(;
    tamanho_bloco::Integer = 32,
    perturbacoes_por_par::Integer = 5,
) = AtaqueCoberturaDependencia(Int(tamanho_bloco), Int(perturbacoes_por_par))

nome(::AtaqueCoberturaDependencia) = "Cobertura de dependência (matriz entrada x saída)"

function executar(a::AtaqueCoberturaDependencia, alvo::AlvoCriptografico)
    tamanho = a.tamanho_bloco
    chave_base = zeros(UInt8, tamanho)
    iv = random_bytes(tamanho_iv(alvo))

    ks_base = gerar_keystream_bruto(alvo, chave_base, iv, "enc", tamanho)
    if length(chave_base) != tamanho
        # A chave precisa ter o mesmo tamanho do bloco pra esse teste
        # isolar 1 posição de cada vez sem wraparound. Se a cifra usa
        # chave de outro tamanho, pula esse ataque.
        throw(SkipAtaqueException("Teste requer chave do mesmo tamanho do bloco."))
    end

    pares_independentes = String[]

    for pos_entrada in 0:(tamanho-1)
        afetou_alguma_saida = falses(tamanho)

        for _ in 1:(a.perturbacoes_por_par)
            chave_teste = copy(chave_base)
            chave_teste[pos_entrada+1] = UInt8(random_int(1, 255))
            ks = gerar_keystream_bruto(alvo, chave_teste, iv, "enc", tamanho)

            for pos_saida in 0:(tamanho-1)
                if ks[pos_saida+1] != ks_base[pos_saida+1]
                    afetou_alguma_saida[pos_saida+1] = true
                end
            end
        end

        for pos_saida in 0:(tamanho-1)
            if !afetou_alguma_saida[pos_saida+1]
                push!(pares_independentes, "entrada[$pos_entrada] -> saída[$pos_saida]")
            end
        end
    end

    if !isempty(pares_independentes)
        return ResultadoAtaque(
            nome(a),
            true,
            "media",
            "$(length(pares_independentes)) par(es) sem dependência detectável em $(a.perturbacoes_por_par) tentativas cada",
            Dict{String,Any}(
                "pares" => pares_independentes[1:min(20, length(pares_independentes))],
            ),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todos os $(tamanho * tamanho) pares (entrada, saída) mostraram dependência",
    )
end

"""
Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
"""
struct AtaqueCoberturaDependenciaIV <: Ataque
    tamanho_bloco::Int
    perturbacoes_por_posicao::Int
end

AtaqueCoberturaDependenciaIV(;
    tamanho_bloco::Integer = 32,
    perturbacoes_por_posicao::Integer = 5,
) = AtaqueCoberturaDependenciaIV(Int(tamanho_bloco), Int(perturbacoes_por_posicao))

nome(::AtaqueCoberturaDependenciaIV) = "Cobertura de dependência do IV (entrada x saída)"

function executar(a::AtaqueCoberturaDependenciaIV, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)
    tam_iv = tamanho_iv(alvo)
    iv_base = zeros(UInt8, tam_iv)

    ks_base = gerar_keystream_bruto(alvo, chave, iv_base, "enc", a.tamanho_bloco)

    pares_independentes = String[]

    for pos_iv in 0:(tam_iv-1)
        afetou = falses(a.tamanho_bloco)

        for _ in 1:(a.perturbacoes_por_posicao)
            iv = copy(iv_base)
            iv[pos_iv+1] = UInt8(random_int(1, 255))
            ks = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho_bloco)

            for pos_saida in 0:(a.tamanho_bloco-1)
                if ks[pos_saida+1] != ks_base[pos_saida+1]
                    afetou[pos_saida+1] = true
                end
            end
        end

        for pos_saida in 0:(a.tamanho_bloco-1)
            if !afetou[pos_saida+1]
                push!(pares_independentes, "iv[$pos_iv] -> saida[$pos_saida]")
            end
        end
    end

    if !isempty(pares_independentes)
        return ResultadoAtaque(
            nome(a),
            true,
            "alta",
            "$(length(pares_independentes)) par(es) sem dependência detectável em $(a.perturbacoes_por_posicao) tentativas cada",
            Dict{String,Any}(
                "pares" => pares_independentes[1:min(20, length(pares_independentes))],
            ),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todas as $tam_iv posições do IV influenciam todas as $(a.tamanho_bloco) posições de saída",
    )
end

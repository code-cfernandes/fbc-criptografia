"""Orquestra a execução de uma coleção de ataques contra um alvo."""
mutable struct SuiteDeAtaques
    ataques::Vector{Ataque}
    SuiteDeAtaques(ataques::Vector{Ataque}) = new(ataques)
end

SuiteDeAtaques() = SuiteDeAtaques(Ataque[])

function adicionar(suite::SuiteDeAtaques, ataque::Ataque)
    push!(suite.ataques, ataque)
    return suite
end

function rodar(suite::SuiteDeAtaques, alvo::AlvoCriptografico)
    resultados = ResultadoAtaque[]
    for ataque in suite.ataques
        try
            push!(resultados, executar(ataque, alvo))
        catch e
            if e isa SkipAtaqueException
                push!(
                    resultados,
                    ResultadoAtaque(nome(ataque), false, "pulado", "Pulado: " * e.msg),
                )
            else
                push!(
                    resultados,
                    ResultadoAtaque(
                        nome(ataque),
                        true,
                        "erro",
                        "Erro ao executar: " * sprint(showerror, e),
                    ),
                )
            end
        end
    end
    return resultados
end

"""Roda e imprime um relatório direto no stdout. Retorna true se passou."""
function rodar_e_imprimir(suite::SuiteDeAtaques, alvo::AlvoCriptografico)
    resultados = rodar(suite, alvo)
    vulnerabilidades = 0

    println("="^70)
    println("RELATÓRIO DA SUÍTE DE ATAQUES")
    println("="^70)
    println()

    for r in resultados
        println(linha_resumo(r))
        if r.vulneravel && r.severidade != "pulado" && r.severidade != "demonstracao"
            vulnerabilidades += 1
        end
    end

    println()
    println("="^70)
    if vulnerabilidades == 0
        println("RESUMO: nenhuma vulnerabilidade encontrada em $(length(resultados)) ataque(s).")
    else
        println(
            "RESUMO: $vulnerabilidades vulnerabilidade(s) encontrada(s) de $(length(resultados)) ataque(s) rodados!",
        )
    end
    println("="^70)

    return vulnerabilidades == 0
end

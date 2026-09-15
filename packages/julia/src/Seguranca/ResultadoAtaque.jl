"""
Resultado de rodar um ataque contra um alvo.

`vulneravel = true` significa que o ataque ACHOU um problema (a cifra falhou).
`vulneravel = false` significa que a cifra resistiu a esse ataque específico.
"""
struct ResultadoAtaque
    nome_ataque::String
    vulneravel::Bool
    severidade::String
    detalhes::String
    dados::Union{Nothing,Dict{String,Any}}
end

function ResultadoAtaque(
    nome_ataque::AbstractString,
    vulneravel::Bool,
    severidade::AbstractString,
    detalhes::AbstractString,
)
    return ResultadoAtaque(
        String(nome_ataque),
        vulneravel,
        String(severidade),
        String(detalhes),
        nothing,
    )
end

function linha_resumo(r::ResultadoAtaque)
    status = if r.severidade == "pulado"
        "PULADO"
    elseif r.severidade == "demonstracao"
        "DEMONSTRAÇÃO"
    elseif r.vulneravel
        "❌ VULNERÁVEL"
    else
        "✅ resistiu"
    end

    return "[$status] $(r.nome_ataque) ($(r.severidade)): $(r.detalhes)"
end

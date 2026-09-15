#!/usr/bin/env julia
"""Análise estática do pacote CriptografiaFBC com Aqua.jl e JET.jl.

O módulo é carregado como pacote de verdade (via `LOAD_PATH`), e não com
`include`, porque o Aqua rejeita módulos que não são pacotes ("Non-package
(non-toplevel) module is not supported"). O ambiente Julia ativo continua sendo
o padrão do usuário, onde Aqua e JET estão instalados; só adicionamos a raiz do
pacote à pilha de `LOAD_PATH`.

Uso: julia --startup-file=no bin/analise.jl
Sai com 0 quando Aqua e JET não apontam problemas e 1 caso contrário.
"""

push!(LOAD_PATH, normpath(joinpath(@__DIR__, "..")))

using CriptografiaFBC
using Aqua
using JET

falhas = String[]

println("="^72)
println("ANÁLISE ESTÁTICA — CriptografiaFBC")
println("="^72)

# ---------------------------------------------------------------------------
# Aqua.jl
# ---------------------------------------------------------------------------
println("\n[Aqua] test_all")
try
    # `project_extras`, `stale_deps` e `deps_compat` dependem de metadados de
    # registro e de um `test/Project.toml` que este pacote não mantém (não é
    # publicado; os runners usam `include`). Os demais testes — ambiguidades,
    # parâmetros de tipo não-ligados, exports indefinidos, pirataria de métodos
    # e tarefas persistentes — rodam normalmente.
    Aqua.test_all(
        CriptografiaFBC;
        project_extras = false,
        stale_deps = false,
        deps_compat = false,
    )
    println("Aqua: OK")
catch e
    push!(falhas, "Aqua: " * sprint(showerror, e))
end

# ---------------------------------------------------------------------------
# JET.jl
# ---------------------------------------------------------------------------
println("\n[JET] report_package")
try
    resultado = JET.report_package(CriptografiaFBC)
    relatorios = JET.get_reports(resultado)
    n = length(relatorios)
    if n == 0
        println("JET: nenhum erro em potencial detectado.")
    else
        show(stdout, MIME("text/plain"), resultado)
        println()
        push!(falhas, "JET: $n erro(s) em potencial detectado(s).")
    end
catch e
    push!(falhas, "JET: " * sprint(showerror, e))
end

# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------
println("\n" * "="^72)
if isempty(falhas)
    println("ANÁLISE ESTÁTICA: OK")
    println("="^72)
    exit(0)
else
    println("ANÁLISE ESTÁTICA: FALHOU")
    for falha in falhas
        println("  - " * falha)
    end
    println("="^72)
    exit(1)
end

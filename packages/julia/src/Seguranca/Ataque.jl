"""
Tipo abstrato de um ataque.

Cada ataque concreto é um `struct ... <: Ataque` que define `nome(a)` e
`executar(a, alvo)`. `executar` deve lançar `SkipAtaqueException` se o alvo
não suportar os recursos necessários.
"""
abstract type Ataque end

function nome end
function executar end

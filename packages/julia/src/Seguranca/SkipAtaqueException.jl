"""Lançada quando o alvo não suporta os recursos que um ataque precisa."""
struct SkipAtaqueException <: Exception
    msg::String
end

Base.showerror(io::IO, e::SkipAtaqueException) = print(io, e.msg)

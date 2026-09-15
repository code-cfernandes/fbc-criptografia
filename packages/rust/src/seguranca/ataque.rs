//! Contrato dos ataques.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::resultado_ataque::ResultadoAtaque;

/// Erro de execução de um ataque.
///
/// `Skip` corresponde à `SkipAtaqueException` (o alvo não suporta o que o
/// ataque precisa). `Falha` corresponde a qualquer exceção inesperada.
#[derive(Debug, Clone)]
pub enum ErroAtaque {
    Skip(String),
    Falha(String),
}

pub trait Ataque {
    fn nome(&self) -> String;

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque>;
}

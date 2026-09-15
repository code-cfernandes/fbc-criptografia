//! O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
//! verdade: todos os 256 valores de byte, NUL, sequências aleatórias de
//! vários tamanhos. Erros de manipulação de string (trim, encoding, NUL
//! truncation) só aparecem com bytes arbitrários.
//!
//! Adaptação Rust: `decrypt` devolve `String` (via `from_utf8_lossy`), então
//! comparamos com a representação UTF-8 dos mesmos bytes.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueIdaEVoltaBinario {
    pub tamanho_maximo: usize,
}

impl AtaqueIdaEVoltaBinario {
    pub fn new() -> Self {
        AtaqueIdaEVoltaBinario {
            tamanho_maximo: 256,
        }
    }
}

impl Default for AtaqueIdaEVoltaBinario {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueIdaEVoltaBinario {
    fn nome(&self) -> String {
        "Ida-e-volta com dados binários (inclui NUL)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut falhas: Vec<String> = Vec::new();

        for len in 0..=self.tamanho_maximo {
            let texto = if len == 0 {
                Vec::new()
            } else {
                random_bytes(len)
            };
            let esperado = String::from_utf8_lossy(&texto).into_owned();
            match alvo.encrypt(&texto) {
                Ok(token) => match alvo.decrypt(&token) {
                    Ok(decifrado) => {
                        if decifrado != esperado {
                            falhas.push(len.to_string());
                        }
                    }
                    Err(e) => falhas.push(format!("{} (erro: {})", len, e)),
                },
                Err(e) => falhas.push(format!("{} (erro: {})", len, e)),
            }
        }

        let todos: Vec<u8> = (0..=255u16).map(|i| i as u8).collect();
        let esperado_todos = String::from_utf8_lossy(&todos).into_owned();
        let token_todos = alvo
            .encrypt(&todos)
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let decifrado_todos = alvo
            .decrypt(&token_todos)
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        if decifrado_todos != esperado_todos {
            falhas.push("todos os 256 valores de byte".to_string());
        }

        if !falhas.is_empty() {
            let amostra: Vec<String> = falhas.iter().take(10).cloned().collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "Falhou em {} caso(s): {}",
                    falhas.len(),
                    amostra.join(", ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todos os tamanhos 0..{} e os 256 valores de byte preservados",
                self.tamanho_maximo
            ),
        ))
    }
}

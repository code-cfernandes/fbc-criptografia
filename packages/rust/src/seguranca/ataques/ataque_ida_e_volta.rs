//! Checagem de sanidade: encrypt seguido de decrypt devolve o original.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueIdaEVolta {
    pub tamanho_maximo: usize,
}

impl AtaqueIdaEVolta {
    pub fn new() -> Self {
        AtaqueIdaEVolta {
            tamanho_maximo: 130,
        }
    }
}

impl Default for AtaqueIdaEVolta {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueIdaEVolta {
    fn nome(&self) -> String {
        "Ida-e-volta (round trip)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut falhas: Vec<String> = Vec::new();

        for len in 0..=self.tamanho_maximo {
            let texto = "Q".repeat(len);
            match alvo.encrypt(texto.as_bytes()) {
                Ok(token) => match alvo.decrypt(&token) {
                    Ok(decifrado) => {
                        if decifrado != texto {
                            falhas.push(len.to_string());
                        }
                    }
                    Err(e) => falhas.push(format!("{} (erro: {})", len, e)),
                },
                Err(e) => falhas.push(format!("{} (erro: {})", len, e)),
            }
        }

        if !falhas.is_empty() {
            let amostra: Vec<String> = falhas.iter().take(10).cloned().collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "Falhou em {} tamanho(s): {}",
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
                "Todos os {} tamanhos (0 a {}) OK",
                self.tamanho_maximo + 1,
                self.tamanho_maximo
            ),
        ))
    }
}

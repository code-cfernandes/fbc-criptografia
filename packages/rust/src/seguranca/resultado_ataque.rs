//! Resultado de rodar um ataque contra um alvo.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severidade {
    Critica,
    Alta,
    Media,
    Baixa,
    Info,
    Pulado,
    Demonstracao,
    Erro,
}

impl Severidade {
    pub fn como_str(&self) -> &'static str {
        match self {
            Severidade::Critica => "critica",
            Severidade::Alta => "alta",
            Severidade::Media => "media",
            Severidade::Baixa => "baixa",
            Severidade::Info => "info",
            Severidade::Pulado => "pulado",
            Severidade::Demonstracao => "demonstracao",
            Severidade::Erro => "erro",
        }
    }
}

impl fmt::Display for Severidade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.como_str())
    }
}

/// `vulneravel = true` significa que o ataque ACHOU um problema (a cifra falhou).
/// `vulneravel = false` significa que a cifra resistiu a esse ataque específico.
#[derive(Debug, Clone)]
pub struct ResultadoAtaque {
    pub nome_ataque: String,
    pub vulneravel: bool,
    pub severidade: Severidade,
    pub detalhes: String,
}

impl ResultadoAtaque {
    pub fn new(
        nome_ataque: &str,
        vulneravel: bool,
        severidade: Severidade,
        detalhes: &str,
    ) -> Self {
        ResultadoAtaque {
            nome_ataque: nome_ataque.to_string(),
            vulneravel,
            severidade,
            detalhes: detalhes.to_string(),
        }
    }

    pub fn linha_resumo(&self) -> String {
        let status = match self.severidade {
            Severidade::Pulado => "PULADO".to_string(),
            Severidade::Demonstracao => "DEMONSTRAÇÃO".to_string(),
            _ => {
                if self.vulneravel {
                    "❌ VULNERÁVEL".to_string()
                } else {
                    "✅ resistiu".to_string()
                }
            }
        };

        format!(
            "[{}] {} ({}): {}",
            status, self.nome_ataque, self.severidade, self.detalhes
        )
    }
}

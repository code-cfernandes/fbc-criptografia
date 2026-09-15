//! A chave precisa ter exatamente 32 bytes; tamanhos errados devem ser
//! rejeitados e uma chave válida deve funcionar.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueValidacaoChave {
    pub tamanhos: Vec<usize>,
}

impl AtaqueValidacaoChave {
    pub fn new() -> Self {
        AtaqueValidacaoChave {
            tamanhos: vec![0, 1, 16, 31, 33, 64],
        }
    }
}

impl Default for AtaqueValidacaoChave {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueValidacaoChave {
    fn nome(&self) -> String {
        "Validação do tamanho da chave".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de CriptografiaAlvo para trocar a chave.".to_string(),
            ));
        }

        let chave_original = alvo.chave_de_teste();
        let mut aceitas_indevidamente: Vec<usize> = Vec::new();
        let mut valida_rejeitada = false;

        for &len in &self.tamanhos {
            CriptografiaAlvo::com_chave(&"K".repeat(len));
            if alvo.encrypt(b"x").is_ok() {
                aceitas_indevidamente.push(len);
            }
        }

        CriptografiaAlvo::com_chave(&"K".repeat(32));
        if alvo.encrypt(b"x").is_err() {
            valida_rejeitada = true;
        }

        CriptografiaAlvo::restaurar_chave(&chave_original);

        let vulneravel = !aceitas_indevidamente.is_empty() || valida_rejeitada;

        let mut detalhes: Vec<String> = Vec::new();
        if !aceitas_indevidamente.is_empty() {
            let lista: Vec<String> = aceitas_indevidamente.iter().map(|n| n.to_string()).collect();
            detalhes.push(format!(
                "chaves de tamanho inválido aceitas: {}",
                lista.join(", ")
            ));
        }
        if valida_rejeitada {
            detalhes.push("chave válida de 32 bytes foi rejeitada".to_string());
        }

        let texto = if vulneravel {
            detalhes.join("; ")
        } else {
            "Tamanhos inválidos rejeitados e chave de 32 bytes aceita".to_string()
        };

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &texto,
        ))
    }
}

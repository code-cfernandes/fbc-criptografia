//! Garante que um token só decifra com a chave correta.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_encode, random_bytes};

pub struct AtaqueChaveErrada {
    pub tentativas: usize,
}

impl AtaqueChaveErrada {
    pub fn new() -> Self {
        AtaqueChaveErrada { tentativas: 30 }
    }
}

impl Default for AtaqueChaveErrada {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueChaveErrada {
    fn nome(&self) -> String {
        "Rejeição de chave incorreta".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de CriptografiaAlvo para trocar a chave.".to_string(),
            ));
        }

        let chave_original = alvo.chave_de_teste();

        let mut tokens: Vec<String> = Vec::new();
        for i in 0..self.tentativas {
            tokens.push(
                alvo.encrypt(format!("MENSAGEM_SECRETA_{}", i).as_bytes())
                    .map_err(|e| ErroAtaque::Falha(e.to_string()))?,
            );
        }

        let mut aceitos: Vec<String> = Vec::new();
        for (i, token) in tokens.iter().enumerate() {
            let chave_errada = hex_encode(&random_bytes(16));
            CriptografiaAlvo::com_chave(&chave_errada);
            if let Ok(r) = alvo.decrypt(token) {
                aceitos.push(format!("tentativa {} aceitou (retornou {})", i, r));
            }
        }
        CriptografiaAlvo::restaurar_chave(&chave_original);

        if !aceitos.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "{} de {} tokens foram aceitos com a chave errada",
                    aceitos.len(),
                    self.tentativas
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Nenhum dos {} tokens foi aceito com chave incorreta",
                self.tentativas
            ),
        ))
    }
}

//! Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
//! garantias de confidencialidade (keystream reusado = "two-time pad").

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::hex_encode;

pub struct AtaqueColisaoIV {
    pub geracoes: usize,
}

impl AtaqueColisaoIV {
    pub fn new() -> Self {
        AtaqueColisaoIV { geracoes: 5000 }
    }
}

impl Default for AtaqueColisaoIV {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueColisaoIV {
    fn nome(&self) -> String {
        "Colisão de IV".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_decode do alvo.".to_string(),
            ));
        }

        let mut vistos: HashSet<String> = HashSet::new();
        let mut colisoes = 0usize;

        for _ in 0..self.geracoes {
            let token = alvo
                .encrypt(b"MESMO_TEXTO_SEMPRE")
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let decodificado = alvo
                .base64url_decode(&token[alvo.prefixo().len()..])
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let iv = alvo.decompor(&decodificado).iv;
            let chave_iv = hex_encode(&iv);
            if !vistos.insert(chave_iv) {
                colisoes += 1;
            }
        }

        if colisoes > 0 {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "{} colisão(ões) de IV em {} gerações",
                    colisoes, self.geracoes
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!("0 colisões em {} gerações", self.geracoes),
        ))
    }
}

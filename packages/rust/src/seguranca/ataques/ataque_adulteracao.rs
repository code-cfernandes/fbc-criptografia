//! Se um bit flipado em QUALQUER campo do token ainda decifra "com sucesso",
//! a cifra não está autenticando o conteúdo.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_int;

pub struct AtaqueAdulteracao {
    pub tentativas: usize,
}

impl AtaqueAdulteracao {
    pub fn new() -> Self {
        AtaqueAdulteracao { tentativas: 500 }
    }
}

impl Default for AtaqueAdulteracao {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueAdulteracao {
    fn nome(&self) -> String {
        "Adulteração de bits (integridade)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_encode/decode do alvo.".to_string(),
            ));
        }

        let mut aceitos_indevidamente: Vec<String> = Vec::new();

        for t in 0..self.tentativas {
            let sufixo = "X".repeat(random_int(0, 50) as usize);
            let texto = format!("MSG_{}{}", t, sufixo);

            let token = alvo
                .encrypt(texto.as_bytes())
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let decodificado = alvo
                .base64url_decode(&token[alvo.prefixo().len()..])
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let mut campos = alvo.decompor(&decodificado);

            let escolha = random_int(0, 2);
            let nome_campo = match escolha {
                0 => "integridade",
                1 => "ciphertext",
                _ => "iv",
            };
            let valor: &mut Vec<u8> = match escolha {
                0 => &mut campos.integridade,
                1 => &mut campos.ciphertext,
                _ => &mut campos.iv,
            };
            if valor.is_empty() {
                continue;
            }

            let pos = random_int(0, valor.len() as i64 - 1) as usize;
            let bit = random_int(0, 7) as u32;
            valor[pos] ^= 1u8 << bit;

            let corpo = alvo.recompor(&campos);
            let token_adulterado =
                format!("{}{}", alvo.prefixo(), alvo.base64url_encode(&corpo));

            if let Ok(resultado) = alvo.decrypt(&token_adulterado) {
                aceitos_indevidamente.push(format!(
                    "campo={}, texto original={}, resultado aceito={}",
                    nome_campo, texto, resultado
                ));
            }
        }

        if !aceitos_indevidamente.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "{} de {} tokens adulterados foram ACEITOS",
                    aceitos_indevidamente.len(),
                    self.tentativas
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!("Todas as {} adulterações foram rejeitadas", self.tentativas),
        ))
    }
}

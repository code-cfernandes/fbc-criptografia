//! Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
//! (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
//! Com um MAC de 32 bytes, nenhuma tentativa deveria passar.

use crate::seguranca::alvo_criptografico::{AlvoCriptografico, CamposToken};
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueMac {
    pub mensagem: String,
}

impl AtaqueMac {
    pub fn new() -> Self {
        AtaqueMac {
            mensagem: "mensagem para o ataque de MAC".to_string(),
        }
    }
}

impl Default for AtaqueMac {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueMac {
    fn nome(&self) -> String {
        "Força bruta e truncamento do MAC".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let token = alvo
            .encrypt(self.mensagem.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let decoded = alvo
            .base64url_decode(&token[alvo.prefixo().len()..])
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let campos = alvo.decompor(&decoded);

        let montar = |integridade: Vec<u8>| -> String {
            let campos_variante = CamposToken {
                integridade,
                ciphertext: campos.ciphertext.clone(),
                iv: campos.iv.clone(),
            };
            format!(
                "{}{}",
                alvo.prefixo(),
                alvo.base64url_encode(&alvo.recompor(&campos_variante))
            )
        };

        let mut aceitos: Vec<String> = Vec::new();

        // 1) integridade zerada
        if alvo
            .decrypt(&montar(vec![0x00u8; campos.integridade.len()]))
            .is_ok()
        {
            aceitos.push("integridade zerada".to_string());
        }

        // 2) integridade truncada pela metade
        let truncada = campos.integridade[..16.min(campos.integridade.len())].to_vec();
        if alvo.decrypt(&montar(truncada)).is_ok() {
            aceitos.push("integridade truncada (16 bytes)".to_string());
        }

        // 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
        // que reconstruiria o próprio token válido e não é uma forja)
        let base = campos.integridade.clone();
        for v in 0..256u16 {
            let v = v as u8;
            if v == base[0] {
                continue;
            }
            let mut tentativa = base.clone();
            tentativa[0] = v;
            if alvo.decrypt(&montar(tentativa)).is_ok() {
                aceitos.push(format!("byte 0 do MAC = {}", v));
            }
        }

        let vulneravel = !aceitos.is_empty();

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &if vulneravel {
                let amostra: Vec<String> = aceitos.iter().take(5).cloned().collect();
                format!(
                    "{} variante(s) de MAC aceitas: {}",
                    aceitos.len(),
                    amostra.join("; ")
                )
            } else {
                "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita"
                    .to_string()
            },
        ))
    }
}

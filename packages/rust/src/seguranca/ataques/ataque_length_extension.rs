//! Length extension / truncamento: a estrutura do token é
//! integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
//! Truncar, estender ou deslocar bytes não pode produzir um token aceito.

use crate::seguranca::alvo_criptografico::{AlvoCriptografico, CamposToken};
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueLengthExtension {
    pub mensagem: String,
}

impl AtaqueLengthExtension {
    pub fn new() -> Self {
        AtaqueLengthExtension {
            mensagem: "texto para o ataque de length extension".to_string(),
        }
    }
}

impl Default for AtaqueLengthExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueLengthExtension {
    fn nome(&self) -> String {
        "Length extension / truncamento de token".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let prefixo = alvo.prefixo();
        let token = alvo
            .encrypt(self.mensagem.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let corpo = &token[prefixo.len()..];
        let meio = corpo.len() / 2;

        let mut variantes: Vec<(String, String)> = Vec::new();
        variantes.push((
            "append A".to_string(),
            format!("{}{}A", prefixo, corpo),
        ));
        variantes.push((
            "append =".to_string(),
            format!("{}{}=", prefixo, corpo),
        ));
        variantes.push((
            "truncar 1 char".to_string(),
            format!("{}{}", prefixo, &corpo[..corpo.len() - 1]),
        ));
        variantes.push((
            "truncar 2 chars".to_string(),
            format!("{}{}", prefixo, &corpo[..corpo.len() - 2]),
        ));
        variantes.push((
            "inserir ! no meio".to_string(),
            format!("{}{}!{}", prefixo, &corpo[..meio], &corpo[meio..]),
        ));
        variantes.push((
            "prefixo extra".to_string(),
            format!("{}A{}", prefixo, corpo),
        ));

        // variantes que mexem nos campos decodificados
        if let Ok(decoded) = alvo.base64url_decode(corpo) {
            let campos = alvo.decompor(&decoded);

            let mut ct_maior = campos.ciphertext.clone();
            ct_maior.push(0x41);
            let campos_ct_maior = CamposToken {
                integridade: campos.integridade.clone(),
                ciphertext: ct_maior,
                iv: campos.iv.clone(),
            };
            variantes.push((
                "ciphertext +1 byte".to_string(),
                format!(
                    "{}{}",
                    prefixo,
                    alvo.base64url_encode(&alvo.recompor(&campos_ct_maior))
                ),
            ));

            let fim = campos.ciphertext.len().saturating_sub(1);
            let ct_menor = campos.ciphertext[..fim].to_vec();
            let campos_ct_menor = CamposToken {
                integridade: campos.integridade.clone(),
                ciphertext: ct_menor,
                iv: campos.iv.clone(),
            };
            variantes.push((
                "ciphertext -1 byte".to_string(),
                format!(
                    "{}{}",
                    prefixo,
                    alvo.base64url_encode(&alvo.recompor(&campos_ct_menor))
                ),
            ));

            let mut iv_maior = campos.iv.clone();
            iv_maior.push(0x42);
            let campos_iv_maior = CamposToken {
                integridade: campos.integridade.clone(),
                ciphertext: campos.ciphertext.clone(),
                iv: iv_maior,
            };
            variantes.push((
                "iv +1 byte".to_string(),
                format!(
                    "{}{}",
                    prefixo,
                    alvo.base64url_encode(&alvo.recompor(&campos_iv_maior))
                ),
            ));
        }

        let mut aceitas: Vec<String> = Vec::new();
        for (nome, v) in &variantes {
            if v == &token {
                continue;
            }
            if alvo.decrypt(v).is_ok() {
                aceitas.push(nome.clone());
            }
        }

        let vulneravel = !aceitas.is_empty();

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &if vulneravel {
                format!(
                    "{} variante(s) aceita(s): {}",
                    aceitas.len(),
                    aceitas.join("; ")
                )
            } else {
                format!(
                    "Todas as {} variantes de truncamento/extensão foram rejeitadas",
                    variantes.len()
                )
            },
        ))
    }
}

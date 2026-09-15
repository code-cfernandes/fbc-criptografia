//! O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
//! ambíguo, um atacante pode reordenar/deslocar os campos e construir um
//! token que sistemas diferentes interpretam de formas diferentes. Todos os
//! rearranjos devem ser rejeitados pela integridade.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueConfusaoCampos;

impl Ataque for AtaqueConfusaoCampos {
    fn nome(&self) -> String {
        "Confusão de campos do token (reordenação/deslocamento)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_encode/decode do alvo.".to_string(),
            ));
        }

        let texto = "MENSAGEM_PARA_TESTE_DE_CAMPOS";
        let token = alvo
            .encrypt(texto.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let prefixo = alvo.prefixo();
        let decodificado = alvo
            .base64url_decode(&token[prefixo.len()..])
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let campos = alvo.decompor(&decodificado);

        let integridade = &campos.integridade;
        let ciphertext = &campos.ciphertext;
        let iv = &campos.iv;

        let mut iv_rotacionado = iv.clone();
        iv_rotacionado.reverse();

        let variantes: Vec<(&str, Vec<u8>)> = vec![
            (
                "iv no início",
                [iv.clone(), integridade.clone(), ciphertext.clone()].concat(),
            ),
            (
                "ciphertext antes da integridade",
                [ciphertext.clone(), integridade.clone(), iv.clone()].concat(),
            ),
            (
                "iv duplicado no fim",
                [integridade.clone(), ciphertext.clone(), iv.clone(), iv.clone()].concat(),
            ),
            (
                "integridade encurtada",
                [integridade[1..].to_vec(), ciphertext.clone(), iv.clone()].concat(),
            ),
            (
                "byte extra no início",
                [b"X".to_vec(), integridade.clone(), ciphertext.clone(), iv.clone()].concat(),
            ),
            (
                "byte extra entre integridade e ciphertext",
                [integridade.clone(), b"X".to_vec(), ciphertext.clone(), iv.clone()].concat(),
            ),
            (
                "byte extra antes do iv",
                [integridade.clone(), ciphertext.clone(), b"X".to_vec(), iv.clone()].concat(),
            ),
            (
                "iv rotacionado",
                [integridade.clone(), ciphertext.clone(), iv_rotacionado].concat(),
            ),
            (
                "iv e último byte do ciphertext trocados",
                [
                    integridade.clone(),
                    ciphertext[..ciphertext.len() - 1].to_vec(),
                    iv.clone(),
                    ciphertext[ciphertext.len() - 1..].to_vec(),
                ]
                .concat(),
            ),
        ];

        let mut aceitas: Vec<String> = Vec::new();
        for (nome, bruto) in &variantes {
            let token_variante = format!("{}{}", prefixo, alvo.base64url_encode(bruto));
            if let Ok(r) = alvo.decrypt(&token_variante) {
                aceitas.push(format!(
                    "{} -> aceito (retornou {} bytes)",
                    nome,
                    r.len()
                ));
            }
        }

        if !aceitas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!("{} rearranjo(s) de campo foram aceitos", aceitas.len()),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todos os {} rearranjos de campo foram rejeitados",
                variantes.len()
            ),
        ))
    }
}

//! Um mesmo token não deveria ter múltiplas representações textuais válidas.
//! Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
//! padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
//! lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
//! token. Isso é "token smuggling": sistemas que comparam/usam a string do
//! token de formas diferentes (cache, WAF, deduplicação/replay) discordam
//! sobre o que ele significa.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::criptografia_alvo::CriptografiaAlvo;
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueCanonicalizacaoToken;

impl Ataque for AtaqueCanonicalizacaoToken {
    fn nome(&self) -> String {
        "Canonicalização do token (base64 não-canônico)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        if alvo.as_any().downcast_ref::<CriptografiaAlvo>().is_none() {
            return Err(ErroAtaque::Skip(
                "Precisa de base64url_encode/decode do alvo.".to_string(),
            ));
        }

        let texto = "MENSAGEM_DE_TESTE_DE_CANONICALIZACAO";
        let token = alvo
            .encrypt(texto.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let prefixo = alvo.prefixo();
        let corpo = &token[prefixo.len()..];
        let meio = corpo.len() / 2;

        let mut variantes: Vec<(String, String)> = Vec::new();
        for &p in &[0usize, meio, corpo.len() - 1] {
            let (antes, depois) = corpo.split_at(p);
            variantes.push((
                format!("espaço na posição {}", p),
                format!("{}{} {}", prefixo, antes, depois),
            ));
            variantes.push((
                format!("newline na posição {}", p),
                format!("{}{}\n{}", prefixo, antes, depois),
            ));
            variantes.push((
                format!("tab na posição {}", p),
                format!("{}{}\t{}", prefixo, antes, depois),
            ));
        }
        variantes.push((
            "alfabeto padrão (+/)".to_string(),
            format!("{}{}", prefixo, corpo.replace('-', "+").replace('_', "/")),
        ));
        variantes.push((
            "padding \"=\" extra".to_string(),
            format!("{}{}=", prefixo, corpo),
        ));
        variantes.push((
            "caractere inválido no meio".to_string(),
            format!("{}{}!{}", prefixo, &corpo[..meio], &corpo[meio..]),
        ));

        let mut aceitas: Vec<String> = Vec::new();
        for (nome, v) in &variantes {
            if v == &token {
                continue;
            }
            if let Ok(decifrado) = alvo.decrypt(v) {
                if decifrado == texto {
                    aceitas.push(nome.clone());
                }
            }
        }

        if !aceitas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Media,
                &format!(
                    "{} variante(s) textualmente diferente(s) decifram para o mesmo texto: {}",
                    aceitas.len(),
                    aceitas.join("; ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todas as {} variantes não-canônicas foram rejeitadas",
                variantes.len()
            ),
        ))
    }
}

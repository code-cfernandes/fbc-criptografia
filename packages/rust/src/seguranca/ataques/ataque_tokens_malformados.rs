//! Robustez do parser de tokens: qualquer entrada que não seja um token
//! íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
//! devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
//! é uma porta pra bugs de validação e "token smuggling".

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_encode, random_bytes};

pub struct AtaqueTokensMalformados;

impl Ataque for AtaqueTokensMalformados {
    fn nome(&self) -> String {
        "Tokens malformados (fuzzing de entrada)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let token = alvo
            .encrypt(b"MENSAGEM_VALIDA_PARA_TESTE")
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let prefixo = alvo.prefixo();
        let corpo = &token[prefixo.len()..];

        let mut casos: Vec<(String, String)> = Vec::new();
        casos.push(("vazio".to_string(), String::new()));
        casos.push(("só prefixo".to_string(), prefixo.to_string()));
        casos.push(("prefixo errado".to_string(), format!("XXX{}", corpo)));
        casos.push((
            "base64 inválido".to_string(),
            format!("{}!!!@@@###", prefixo),
        ));
        casos.push(("bytes extras no fim".to_string(), format!("{}AAAA", token)));
        casos.push((
            "bytes extras no início".to_string(),
            format!("AAAA{}", token),
        ));

        for len in 1..token.len() {
            casos.push((
                format!("truncado em {}", len),
                token[..len].to_string(),
            ));
        }
        for i in 0..20 {
            casos.push((
                format!("lixo aleatório {}", i),
                format!("{}{}", prefixo, hex_encode(&random_bytes(16))),
            ));
        }

        let mut aceitos: Vec<String> = Vec::new();
        for (nome, t) in &casos {
            if let Ok(r) = alvo.decrypt(t) {
                aceitos.push(format!(
                    "{} -> aceito (retornou {} bytes)",
                    nome,
                    r.len()
                ));
            }
        }

        if !aceitos.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "{} entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas",
                    aceitos.len()
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Todas as {} entradas malformadas foram rejeitadas",
                casos.len()
            ),
        ))
    }
}

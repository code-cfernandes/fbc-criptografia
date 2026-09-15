//! Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
//! sincronização de bloco, repetição de keystream em blocos distantes ou
//! perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
//! curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
//! gera tokens diferentes.
//!
//! Adaptação Rust: `decrypt` devolve `String` (via `from_utf8_lossy`), então
//! comparamos com a representação UTF-8 dos mesmos bytes.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueMensagemLonga {
    pub tamanhos: Vec<usize>,
}

impl AtaqueMensagemLonga {
    pub fn new() -> Self {
        AtaqueMensagemLonga {
            tamanhos: vec![1000, 10000, 100000],
        }
    }
}

impl Default for AtaqueMensagemLonga {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueMensagemLonga {
    fn nome(&self) -> String {
        "Mensagens longas (multi-bloco)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut falhas: Vec<String> = Vec::new();

        for t in &self.tamanhos {
            let texto = random_bytes(*t);
            let esperado = String::from_utf8_lossy(&texto).into_owned();
            match alvo.encrypt(&texto) {
                Ok(token) => match alvo.decrypt(&token) {
                    Ok(decifrado) => {
                        if decifrado != esperado {
                            falhas.push(format!("{} bytes (conteúdo diferente)", t));
                        }
                    }
                    Err(e) => falhas.push(format!("{} bytes (erro: {})", t, e)),
                },
                Err(e) => falhas.push(format!("{} bytes (erro: {})", t, e)),
            }
        }

        let texto = "A".repeat(1000);
        let t1 = alvo
            .encrypt(texto.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        let t2 = alvo
            .encrypt(texto.as_bytes())
            .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
        if t1 == t2 {
            falhas.push("tokens idênticos para o mesmo texto (IV não varia)".to_string());
        }

        if !falhas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!("Falha em: {}", falhas.join("; ")),
            ));
        }

        let lista: Vec<String> = self.tamanhos.iter().map(|t| t.to_string()).collect();
        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Ida-e-volta OK em {} bytes; mesmo texto gera tokens distintos",
                lista.join(", ")
            ),
        ))
    }
}

//! Procura posições de byte que NUNCA mudam entre tokens — âncoras que um
//! atacante poderia usar pra recuperar a chave.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueBytesFixos {
    pub amostras: usize,
}

impl AtaqueBytesFixos {
    pub fn new() -> Self {
        AtaqueBytesFixos { amostras: 30 }
    }
}

impl Default for AtaqueBytesFixos {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueBytesFixos {
    fn nome(&self) -> String {
        "Bytes fixos entre tokens".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let mut decodificados: Vec<Vec<u8>> = Vec::new();

        for i in 0..self.amostras {
            let letra = (b'A' + (i % 26) as u8) as char;
            let sufixo: String = std::iter::repeat_n(letra, i % 10).collect();
            let texto = format!("TEXTO_VARIADO_{}{}", i, sufixo);
            let token = alvo
                .encrypt(texto.as_bytes())
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            let corpo = &token[alvo.prefixo().len()..];
            let decodificado = alvo
                .base64url_decode(corpo)
                .map_err(|e| ErroAtaque::Falha(e.to_string()))?;
            decodificados.push(decodificado);
        }

        let tamanho_minimo = decodificados.iter().map(|d| d.len()).min().unwrap_or(0);
        let mut posicoes_fixas: Vec<usize> = Vec::new();

        for i in 0..tamanho_minimo {
            let primeiro = decodificados[0][i];
            if decodificados.iter().all(|d| d[i] == primeiro) {
                posicoes_fixas.push(i);
            }
        }

        if !posicoes_fixas.is_empty() {
            let amostra: Vec<String> = posicoes_fixas
                .iter()
                .take(10)
                .map(|p| p.to_string())
                .collect();
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &format!(
                    "{} posição(ões) de byte fixas em {} tokens: {}",
                    posicoes_fixas.len(),
                    self.amostras,
                    amostra.join(", ")
                ),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "0 de {} posições fixas em {} tokens",
                tamanho_minimo, self.amostras
            ),
        ))
    }
}

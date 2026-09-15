//! Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
//! (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
//! produzir keystream degenerado - e aqui testamos no pior cenário, com IV
//! zerado junto, pra isolar a contribuição da chave.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueChavesDegeneradas {
    pub tamanho_bloco: usize,
}

impl AtaqueChavesDegeneradas {
    pub fn new() -> Self {
        AtaqueChavesDegeneradas { tamanho_bloco: 32 }
    }
}

impl Default for AtaqueChavesDegeneradas {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueChavesDegeneradas {
    fn nome(&self) -> String {
        "Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tam_chave = alvo.chave_de_teste().len();
        let iv_zero = vec![0u8; alvo.tamanho_iv()];

        let seq_crescente: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();

        let casos: Vec<(&str, Vec<u8>)> = vec![
            ("zero", vec![0u8; tam_chave]),
            ("0xFF", vec![0xffu8; tam_chave]),
            ("alternada 0xAA", vec![0xaau8; tam_chave]),
            ("alternada 0x55", vec![0x55u8; tam_chave]),
            ("repetida \"A\"", vec![0x41u8; tam_chave]),
            ("crescente", seq_crescente[..tam_chave].to_vec()),
        ];

        let mut problemas: Vec<String> = Vec::new();
        for (nome, chave) in &casos {
            let ks = alvo.gerar_keystream_bruto(chave, &iv_zero, "enc", self.tamanho_bloco);

            let metade = self.tamanho_bloco / 2;
            let periodico = ks[0..metade] == ks[metade..metade + metade];
            let bytes_unicos = ks.iter().copied().collect::<HashSet<u8>>().len();

            if periodico || (bytes_unicos as f64) < self.tamanho_bloco as f64 * 0.5 {
                problemas.push(format!(
                    "{} (periódico={}, bytes únicos={}/{})",
                    nome,
                    if periodico { "sim" } else { "não" },
                    bytes_unicos,
                    self.tamanho_bloco
                ));
            }
        }

        if !problemas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Alta,
                &problemas.join("; "),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Nenhuma das {} chaves degeneradas testadas produziu saída anômala",
                casos.len()
            ),
        ))
    }
}

//! Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
//! (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
//! mesmo quando a maioria das entradas se comporta bem. Testa especificamente
//! esses casos extremos, que testes com entrada aleatória raramente cobrem.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};

pub struct AtaqueIVsDegenerados;

impl Ataque for AtaqueIVsDegenerados {
    fn nome(&self) -> String {
        "IVs degenerados (zero, 0xFF, alternado)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();
        let tamanho_iv = alvo.tamanho_iv();
        let tamanho_bloco = 32usize;

        let _primeiro = alvo.gerar_keystream_bruto(
            chave.as_bytes(),
            &vec![0u8; tamanho_iv],
            "enc",
            tamanho_bloco,
        );

        let casos: Vec<(&str, Vec<u8>)> = vec![
            ("zero", vec![0x00u8; tamanho_iv]),
            ("0xFF", vec![0xffu8; tamanho_iv]),
            ("alternado 0xAA", vec![0xaau8; tamanho_iv]),
            ("alternado 0x55", vec![0x55u8; tamanho_iv]),
            (
                "crescente",
                (0..tamanho_iv).map(|i| i as u8).collect(),
            ),
        ];

        let mut problemas: Vec<String> = Vec::new();
        for (nome, iv) in &casos {
            let ks = alvo.gerar_keystream_bruto(chave.as_bytes(), iv, "enc", tamanho_bloco);

            let metade = tamanho_bloco / 2;
            let periodico = ks[0..metade] == ks[metade..metade + metade];

            let bytes_unicos = ks.iter().copied().collect::<HashSet<u8>>().len();
            let pouca_variedade = (bytes_unicos as f64) < tamanho_bloco as f64 * 0.5;

            if periodico || pouca_variedade {
                problemas.push(format!(
                    "{} (periódico={}, bytes únicos={}/{})",
                    nome,
                    if periodico { "sim" } else { "não" },
                    bytes_unicos,
                    tamanho_bloco
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
                "Nenhum dos {} IVs degenerados testados produziu saída anômala",
                casos.len()
            ),
        ))
    }
}

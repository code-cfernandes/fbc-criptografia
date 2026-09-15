//! Esse é o ataque que pegou o bug mais sério que encontramos: quando a
//! distância de mistura era exatamente metade do bloco, TODOS os IVs
//! aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
//! Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::random_bytes;

pub struct AtaqueFoldEstrutural {
    pub amostras: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueFoldEstrutural {
    pub fn new() -> Self {
        AtaqueFoldEstrutural {
            amostras: 5000,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueFoldEstrutural {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueFoldEstrutural {
    fn nome(&self) -> String {
        "Fold estrutural (metades/quartos/oitavos repetidos)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave = alvo.chave_de_teste();

        let divisores: Vec<usize> = [2usize, 4, 8, 16]
            .into_iter()
            .filter(|&d| self.tamanho_bloco.is_multiple_of(d) && self.tamanho_bloco / d >= 1)
            .collect();

        let mut ocorrencias: Vec<(usize, usize)> =
            divisores.iter().map(|&d| (d, 0usize)).collect();

        // Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
        // a chance de colisão por acaso é ~1/256^tam por par comparado -
        // desprezível para tam >= 2, então qualquer contagem > 0 já é
        // suspeita o bastante pra investigar (ajustamos a margem pra
        // fatias de 1-2 bytes, onde colisão por acaso é mais provável).
        for _ in 0..self.amostras {
            let ks = alvo.gerar_keystream_bruto(
                chave.as_bytes(),
                &random_bytes(alvo.tamanho_iv()),
                "enc",
                self.tamanho_bloco,
            );
            for divisor in &divisores {
                let tam_fatia = self.tamanho_bloco / divisor;
                let primeira_fatia = &ks[0..tam_fatia];
                for j in 1..*divisor {
                    if &ks[j * tam_fatia..j * tam_fatia + tam_fatia] == primeira_fatia {
                        if let Some(entry) = ocorrencias.iter_mut().find(|(d, _)| d == divisor) {
                            entry.1 += 1;
                        }
                        break;
                    }
                }
            }
        }

        let margem = |divisor: usize| -> usize {
            if self.tamanho_bloco / divisor <= 2 {
                (self.amostras as f64 * 0.01) as usize + 3
            } else {
                5
            }
        };

        let problemas: Vec<(usize, usize)> = ocorrencias
            .iter()
            .filter(|(d, c)| *c > margem(*d))
            .cloned()
            .collect();

        if !problemas.is_empty() {
            let detalhe = problemas
                .iter()
                .map(|(d, c)| format!("1/{} do bloco repetido em {}/{}", d, c, self.amostras))
                .collect::<Vec<String>>()
                .join(", ");
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &detalhe,
            ));
        }

        let json: Vec<String> = ocorrencias
            .iter()
            .map(|(d, c)| format!("\"{}\":{}", d, c))
            .collect();
        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &("Nenhuma repetição estrutural acima do ruído esperado: {".to_string()
                + &json.join(",")
                + "}"),
        ))
    }
}

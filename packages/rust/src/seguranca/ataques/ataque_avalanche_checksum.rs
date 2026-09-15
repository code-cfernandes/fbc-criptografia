//! O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
//! interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
//! dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
//! posição específica significa que aquele byte quase não influencia o MAC -
//! uma pista forte de que a mistura tem um "ponto cego" estrutural.
//!
//! Varre TODAS as posições/bits da entrada (não amostra aleatória) para
//! apontar exatamente onde está o ponto fraco.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{bits_diferentes, random_bytes};

pub struct AtaqueAvalancheChecksum {
    pub mensagens_por_combinacao: usize,
    pub tamanho_entrada: usize,
    pub limite_media: f64,
    pub limite_pior_caso: f64,
}

impl AtaqueAvalancheChecksum {
    pub fn new() -> Self {
        AtaqueAvalancheChecksum {
            mensagens_por_combinacao: 10,
            tamanho_entrada: 32,
            limite_media: 0.4,
            limite_pior_caso: 0.4,
        }
    }
}

impl Default for AtaqueAvalancheChecksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueAvalancheChecksum {
    fn nome(&self) -> String {
        "Efeito avalanche do checksum/MAC".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_mac = "M".repeat(32);

        let primeiro = alvo.checksum_bruto(b"teste", chave_mac.as_bytes());
        let tamanho_saida = primeiro.len();

        let mut soma_global = 0.0f64;
        let mut combinacoes = 0usize;
        let mut pior = (-1i64, -1i64, 1.0f64);

        for pos in 0..self.tamanho_entrada {
            for bit in 0..8 {
                let mut soma = 0.0f64;
                for _ in 0..self.mensagens_por_combinacao {
                    let entrada = random_bytes(self.tamanho_entrada);
                    let mut alterada = entrada.clone();
                    alterada[pos] ^= 1u8 << (bit as u32);

                    let h1 = alvo.checksum_bruto(&entrada, chave_mac.as_bytes());
                    let h2 = alvo.checksum_bruto(&alterada, chave_mac.as_bytes());

                    soma += bits_diferentes(&h1, &h2) as f64 / (tamanho_saida * 8) as f64;
                }
                let media = soma / self.mensagens_por_combinacao as f64;

                soma_global += media;
                combinacoes += 1;
                if media < pior.2 {
                    pior = (pos as i64, bit as i64, media);
                }
            }
        }

        let media_global = soma_global / combinacoes as f64;
        let vulneravel = media_global < self.limite_media || pior.2 < self.limite_pior_caso;

        let severidade = if !vulneravel {
            Severidade::Info
        } else if pior.2 < 0.3 {
            Severidade::Alta
        } else {
            Severidade::Media
        };

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            severidade,
            &format!(
                "média global={:.1}%; pior caso={:.1}% na entrada[posição={}, bit={}] sobre {} bytes de MAC (limites: média>={:.0}%, pior>={:.0}%)",
                media_global * 100.0,
                pior.2 * 100.0,
                pior.0,
                pior.1,
                tamanho_saida,
                self.limite_media * 100.0,
                self.limite_pior_caso * 100.0
            ),
        ))
    }
}

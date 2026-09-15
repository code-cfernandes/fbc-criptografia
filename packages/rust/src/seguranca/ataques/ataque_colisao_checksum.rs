//! Procura colisões no checksum() via paradoxo do aniversário: gera muitas
//! mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
//! propósito aqui - testar resistência a colisão é uma propriedade do
//! ALGORITMO, independente de a chave ser secreta ou não; é assim que se
//! testa qualquer função de hash/MAC na prática).
//!
//! Testa dois níveis:
//! 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
//!    aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
//!    tentativas pelo paradoxo do aniversário).
//! 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
//!    estatisticamente com poucas dezenas de milhares de tentativas (o
//!    paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
//!    pra 50% de chance). Isso não quebra o MAC completo (que depende dos
//!    32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
//!    útil pra saber se a composição das rodadas está de fato preservando
//!    a força total, ou se há alguma correlação entre elas.

use std::collections::HashMap;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{hex_encode, random_bytes};

pub struct AtaqueColisaoChecksum {
    pub amostras: usize,
}

impl AtaqueColisaoChecksum {
    pub fn new() -> Self {
        AtaqueColisaoChecksum { amostras: 200000 }
    }
}

impl Default for AtaqueColisaoChecksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueColisaoChecksum {
    fn nome(&self) -> String {
        "Colisão no checksum (paradoxo do aniversário)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_de_mac = "M".repeat(32); // chave conhecida de propósito - ver docblock

        let _primeiro = alvo.checksum_bruto(b"teste", chave_de_mac.as_bytes());

        let mut vistos_completo: HashMap<String, Vec<u8>> = HashMap::new();
        let mut vistos_truncado: HashMap<String, Vec<u8>> = HashMap::new();
        let mut colisao_completa: Option<(Vec<u8>, Vec<u8>)> = None;
        let mut colisao_truncada: Option<(Vec<u8>, Vec<u8>)> = None;

        for _ in 0..self.amostras {
            let mensagem = random_bytes(20);
            let hash = alvo.checksum_bruto(&mensagem, chave_de_mac.as_bytes());

            if colisao_completa.is_none() {
                let chave_hash = hex_encode(&hash);
                if let Some(anterior) = vistos_completo.get(&chave_hash) {
                    colisao_completa = Some((anterior.clone(), mensagem.clone()));
                } else {
                    vistos_completo.insert(chave_hash, mensagem.clone());
                }
            }

            if colisao_truncada.is_none() {
                let truncado = hex_encode(&hash[..4]);
                if let Some(anterior) = vistos_truncado.get(&truncado) {
                    colisao_truncada = Some((anterior.clone(), mensagem.clone()));
                } else {
                    vistos_truncado.insert(truncado, mensagem.clone());
                }
            }

            if colisao_completa.is_some() && colisao_truncada.is_some() {
                break;
            }
        }

        // Colisão no checksum COMPLETO com essa amostra pequena seria uma
        // falha estrutural séria (a probabilidade por acaso é desprezível).
        if colisao_completa.is_some() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Critica,
                &format!(
                    "COLISÃO COMPLETA encontrada em {} amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.",
                    vistos_completo.len()
                ),
            ));
        }

        // Colisão truncada (32 bits) é esperada estatisticamente - não é
        // "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
        // força que deveriam ter (nem mais, nem menos).
        let info_truncada = if colisao_truncada.is_some() {
            format!(
                "colisão de 32 bits encontrada em {} amostras (esperado pelo paradoxo do aniversário)",
                vistos_truncado.len()
            )
        } else {
            format!(
                "nenhuma colisão de 32 bits em {} amostras (um pouco abaixo do esperado, mas não conclusivo)",
                vistos_truncado.len()
            )
        };

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "Nenhuma colisão completa em {} amostras (esperado). Nível truncado (32 bits): {}.",
                self.amostras, info_truncada
            ),
        ))
    }
}

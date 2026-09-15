//! A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
//! chave do MAC ('mac'). Se os dois streams não forem independentes, um
//! atacante que recupere o keystream de dados (ataque de texto conhecido)
//! pode derivar a chave do MAC e FORJAR tokens válidos.
//!
//! O teste procura dois sintomas de acoplamento:
//!  1. a distância de Hamming média entre os streams deve ser ~50%;
//!  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
//!     uma máscara fixa, o mac é 100% previsível a partir do enc.

use std::collections::HashSet;

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{bits_diferentes, hex_encode, random_bytes};

pub struct AtaqueIndependenciaProposito {
    pub amostras: usize,
    pub tamanho: usize,
}

impl AtaqueIndependenciaProposito {
    pub fn new() -> Self {
        AtaqueIndependenciaProposito {
            amostras: 2000,
            tamanho: 32,
        }
    }
}

impl Default for AtaqueIndependenciaProposito {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueIndependenciaProposito {
    fn nome(&self) -> String {
        "Independência entre keystreams de propósitos diferentes (enc x mac)".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let tam_chave = alvo.chave_de_teste().len();
        let tam_iv = alvo.tamanho_iv();

        let _primeiro = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(tam_iv),
            "enc",
            self.tamanho,
        );

        let mut distancias: Vec<f64> = Vec::with_capacity(self.amostras);
        let mut mascaras: HashSet<String> = HashSet::new();
        for _ in 0..self.amostras {
            let chave = random_bytes(tam_chave);
            let iv = random_bytes(tam_iv);

            let enc = alvo.gerar_keystream_bruto(&chave, &iv, "enc", self.tamanho);
            let mac = alvo.gerar_keystream_bruto(&chave, &iv, "mac", self.tamanho);

            distancias.push(bits_diferentes(&enc, &mac) as f64 / (self.tamanho * 8) as f64);
            let xor: Vec<u8> = enc.iter().zip(mac.iter()).map(|(a, b)| a ^ b).collect();
            mascaras.insert(hex_encode(&xor));
        }

        let media = distancias.iter().sum::<f64>() / distancias.len() as f64;
        let mascaras_distintas = mascaras.len();

        let vulneravel = media < 0.4 || media > 0.6 || mascaras_distintas < self.amostras;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Critica
            } else {
                Severidade::Info
            },
            &format!(
                "Hamming médio enc x mac={:.1}% (esperado ~50%); {} máscara(s) XOR distinta(s) em {} amostras{}",
                media * 100.0,
                mascaras_distintas,
                self.amostras,
                if mascaras_distintas < self.amostras {
                    " - MÁSCARA REPETIDA: mac previsível a partir de enc!"
                } else {
                    ""
                }
            ),
        ))
    }
}

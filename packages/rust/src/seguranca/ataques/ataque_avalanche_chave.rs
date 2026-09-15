//! O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
//! CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
//! inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
//! Números baixos indicam que parte da chave tem pouca influência - o que
//! reduziria o espaço de busca de um atacante.

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{bits_diferentes, random_bytes, random_int};

pub struct AtaqueAvalancheChave {
    pub amostras: usize,
    pub tamanho_bloco: usize,
    pub limite_media: f64,
    pub limite_pior_caso: f64,
}

impl AtaqueAvalancheChave {
    pub fn new() -> Self {
        AtaqueAvalancheChave {
            amostras: 3000,
            tamanho_bloco: 32,
            limite_media: 0.45,
            limite_pior_caso: 0.3,
        }
    }
}

impl Default for AtaqueAvalancheChave {
    fn default() -> Self {
        Self::new()
    }
}

impl Ataque for AtaqueAvalancheChave {
    fn nome(&self) -> String {
        "Efeito avalanche da chave".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let chave_base = alvo.chave_de_teste().into_bytes();
        let len_chave = chave_base.len();
        let iv = random_bytes(alvo.tamanho_iv());

        let mut valores: Vec<f64> = Vec::with_capacity(self.amostras);
        for _ in 0..self.amostras {
            let mut chave = chave_base.clone();
            let pos = random_int(0, len_chave as i64 - 1) as usize;
            chave[pos] ^= 1u8 << (random_int(0, 7) as u32);

            let ks1 =
                alvo.gerar_keystream_bruto(&chave_base, &iv, "enc", self.tamanho_bloco);
            let ks2 = alvo.gerar_keystream_bruto(&chave, &iv, "enc", self.tamanho_bloco);

            valores.push(bits_diferentes(&ks1, &ks2) as f64 / (self.tamanho_bloco * 8) as f64);
        }

        valores.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = valores.len();
        let media: f64 = valores.iter().sum::<f64>() / n as f64;
        let pior_caso = valores[0];

        let vulneravel = media < self.limite_media || pior_caso < self.limite_pior_caso;

        Ok(ResultadoAtaque::new(
            &self.nome(),
            vulneravel,
            if vulneravel {
                Severidade::Alta
            } else {
                Severidade::Info
            },
            &format!(
                "média={:.1}%, pior caso={:.1}% (limites: média>={:.0}%, pior>={:.0}%)",
                media * 100.0,
                pior_caso * 100.0,
                self.limite_media * 100.0,
                self.limite_pior_caso * 100.0
            ),
        ))
    }
}

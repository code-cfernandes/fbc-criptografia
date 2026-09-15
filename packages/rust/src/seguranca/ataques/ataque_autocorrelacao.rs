//! O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
//! Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
//! autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
//! estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
//! keystream aleatório deve ter todos esses indicadores perto de zero/50%.

use std::collections::{BTreeMap, HashSet};

use crate::seguranca::alvo_criptografico::AlvoCriptografico;
use crate::seguranca::ataque::{Ataque, ErroAtaque};
use crate::seguranca::resultado_ataque::{ResultadoAtaque, Severidade};
use crate::seguranca::util::{contar_bits_buffer, hex_encode, random_bytes};

pub struct AtaqueAutocorrelacao {
    pub tamanho: usize,
    pub tamanho_bloco: usize,
}

impl AtaqueAutocorrelacao {
    pub fn new() -> Self {
        AtaqueAutocorrelacao {
            tamanho: 8192,
            tamanho_bloco: 32,
        }
    }
}

impl Default for AtaqueAutocorrelacao {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaqueAutocorrelacao {
    fn correlacao(s: &[u8], lag: usize) -> f64 {
        let n = s.len();
        if n <= lag {
            return 0.0;
        }

        let soma: u64 = s.iter().map(|&b| b as u64).sum();
        let media = soma as f64 / n as f64;

        let mut num = 0.0f64;
        let mut den = 0.0f64;
        for &v in s.iter() {
            den += (v as f64 - media).powi(2);
        }
        for i in 0..(n - lag) {
            num += (s[i] as f64 - media) * (s[i + lag] as f64 - media);
        }

        if den > 0.0 {
            num / den
        } else {
            0.0
        }
    }
}

impl Ataque for AtaqueAutocorrelacao {
    fn nome(&self) -> String {
        "Autocorrelação e periodicidade do keystream".to_string()
    }

    fn executar(&self, alvo: &dyn AlvoCriptografico) -> Result<ResultadoAtaque, ErroAtaque> {
        let ks = alvo.gerar_keystream_bruto(
            alvo.chave_de_teste().as_bytes(),
            &random_bytes(alvo.tamanho_iv()),
            "enc",
            self.tamanho,
        );

        let serial = Self::correlacao(&ks, 1);

        let mut suspeitos: BTreeMap<usize, f64> = BTreeMap::new();
        for lag in [2usize, 4, 8, 16, 32, 64, 128, 256] {
            let c = Self::correlacao(&ks, lag);
            if c.abs() > 0.1 {
                suspeitos.insert(lag, c);
            }
        }

        let mut blocos: HashSet<String> = HashSet::new();
        let mut num_blocos = 0usize;
        for chunk in ks.chunks(self.tamanho_bloco) {
            blocos.insert(hex_encode(chunk));
            num_blocos += 1;
        }
        let blocos_repetidos = num_blocos - blocos.len();

        let uns = contar_bits_buffer(&ks);
        let fracao_uns = uns as f64 / (ks.len() * 8) as f64;

        let mut problemas: Vec<String> = Vec::new();
        if serial.abs() > 0.1 {
            problemas.push(format!("correlação serial={:.3}", serial));
        }
        if !suspeitos.is_empty() {
            let lags: Vec<String> = suspeitos.keys().map(|l| l.to_string()).collect();
            problemas.push("autocorrelação em lag(s) ".to_string() + &lags.join(", "));
        }
        if blocos_repetidos > 0 {
            problemas.push(format!(
                "{} bloco(s) de {} bytes repetido(s)",
                blocos_repetidos, self.tamanho_bloco
            ));
        }
        if fracao_uns < 0.45 || fracao_uns > 0.55 {
            problemas.push(format!("balanço de bits={:.1}% de 1s", fracao_uns * 100.0));
        }

        if !problemas.is_empty() {
            return Ok(ResultadoAtaque::new(
                &self.nome(),
                true,
                Severidade::Media,
                &problemas.join("; "),
            ));
        }

        Ok(ResultadoAtaque::new(
            &self.nome(),
            false,
            Severidade::Info,
            &format!(
                "serial={:.3}, nenhum lag com correlação >10%, 0 blocos repetidos em {}, {:.1}% de bits 1",
                serial,
                num_blocos,
                fracao_uns * 100.0
            ),
        ))
    }
}

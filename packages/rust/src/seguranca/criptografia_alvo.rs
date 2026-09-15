//! Liga a suíte de ataques à cifra real, expondo as camadas internas de
//! keystream e checksum.

use std::any::Any;

use crate::core::criptografia as cifra;
use crate::core::{CriptoError, TAM_BLOCO};
use crate::seguranca::alvo_criptografico::{AlvoCriptografico, CamposToken};

const CHAVE_PADRAO: &str = "pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf";

pub struct CriptografiaAlvo {
    chave_teste: String,
}

impl CriptografiaAlvo {
    pub fn new() -> Self {
        Self::com_chave(CHAVE_PADRAO)
    }

    /// Cria o alvo e escreve a chave no ambiente do processo (como no TS).
    pub fn com_chave(chave_teste: &str) -> Self {
        std::env::set_var("FBC_KEY", chave_teste);
        CriptografiaAlvo {
            chave_teste: chave_teste.to_string(),
        }
    }

    /// Restaura a chave no ambiente (usado pelos ataques que a trocam).
    pub fn restaurar_chave(chave: &str) {
        std::env::set_var("FBC_KEY", chave);
    }
}

impl Default for CriptografiaAlvo {
    fn default() -> Self {
        Self::new()
    }
}

impl AlvoCriptografico for CriptografiaAlvo {
    fn encrypt(&self, texto: &[u8]) -> Result<String, CriptoError> {
        cifra::encrypt_bytes(texto)
    }

    fn decrypt(&self, token: &str) -> Result<String, CriptoError> {
        cifra::decrypt(token)
    }

    fn prefixo(&self) -> &str {
        "FBC"
    }

    fn decompor(&self, token_decodificado: &[u8]) -> CamposToken {
        let len = token_decodificado.len();
        let tam_iv = self.tamanho_iv();

        let integridade = token_decodificado[0..TAM_BLOCO.min(len)].to_vec();
        let iv = if len >= tam_iv {
            token_decodificado[len - tam_iv..].to_vec()
        } else {
            Vec::new()
        };
        let ciphertext = if len >= TAM_BLOCO + tam_iv {
            token_decodificado[TAM_BLOCO..len - tam_iv].to_vec()
        } else {
            Vec::new()
        };

        CamposToken {
            integridade,
            ciphertext,
            iv,
        }
    }

    fn recompor(&self, campos: &CamposToken) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            campos.integridade.len() + campos.ciphertext.len() + campos.iv.len(),
        );
        out.extend_from_slice(&campos.integridade);
        out.extend_from_slice(&campos.ciphertext);
        out.extend_from_slice(&campos.iv);
        out
    }

    fn gerar_keystream_bruto(
        &self,
        key: &[u8],
        iv: &[u8],
        proposito: &str,
        tamanho: usize,
    ) -> Vec<u8> {
        cifra::gerar_keystream(key, iv, proposito, tamanho)
    }

    fn checksum_bruto(&self, dados: &[u8], key: &[u8]) -> Vec<u8> {
        cifra::checksum(dados, key).to_vec()
    }

    fn chave_de_teste(&self) -> String {
        self.chave_teste.clone()
    }

    fn tamanho_iv(&self) -> usize {
        16
    }

    fn base64url_encode(&self, data: &[u8]) -> String {
        cifra::base64url_encode(data)
    }

    fn base64url_decode(&self, data: &str) -> Result<Vec<u8>, CriptoError> {
        cifra::base64url_decode(data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

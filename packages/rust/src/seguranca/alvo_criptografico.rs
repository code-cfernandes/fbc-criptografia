//! Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.

use std::any::Any;

use crate::core::CriptoError;

/// Campos que compõem um token (já decodificado do base64url).
#[derive(Debug, Clone)]
pub struct CamposToken {
    pub integridade: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

pub trait AlvoCriptografico: Any {
    fn encrypt(&self, texto: &[u8]) -> Result<String, CriptoError>;

    fn decrypt(&self, token: &str) -> Result<String, CriptoError>;

    /// Prefixo esperado no início de um token válido (ex: "FBC").
    fn prefixo(&self) -> &str;

    /// Decompõe um token (sem prefixo e já base64url-decodificado) nos campos.
    fn decompor(&self, token_decodificado: &[u8]) -> CamposToken;

    /// Recompõe um token a partir dos campos (inverso de `decompor`).
    fn recompor(&self, campos: &CamposToken) -> Vec<u8>;

    /// Gera N bytes de keystream bruto a partir de key+iv+propósito.
    fn gerar_keystream_bruto(
        &self,
        key: &[u8],
        iv: &[u8],
        proposito: &str,
        tamanho: usize,
    ) -> Vec<u8>;

    /// Chama o `checksum` interno diretamente.
    fn checksum_bruto(&self, dados: &[u8], key: &[u8]) -> Vec<u8>;

    /// Uma chave válida pra usar nos testes.
    fn chave_de_teste(&self) -> String;

    /// Tamanho do IV em bytes.
    fn tamanho_iv(&self) -> usize;

    fn base64url_encode(&self, data: &[u8]) -> String;

    fn base64url_decode(&self, data: &str) -> Result<Vec<u8>, CriptoError>;

    /// Suporte a downcast para alvos concretos que precisam trocar a chave.
    fn as_any(&self) -> &dyn Any;
}

//! Runner da suíte de ataques da cifra FBC em Rust.
#![allow(dead_code)]

mod core;
mod seguranca;

use seguranca::ataques::ataque_adulteracao::AtaqueAdulteracao;
use seguranca::ataques::ataque_bytes_fixos::AtaqueBytesFixos;
use seguranca::ataques::ataque_chave_errada::AtaqueChaveErrada;
use seguranca::ataques::ataque_colisao_iv::AtaqueColisaoIV;
use seguranca::ataques::ataque_ida_e_volta::AtaqueIdaEVolta;
use seguranca::ataques::ataque_interoperabilidade::AtaqueInteroperabilidade;
use seguranca::ataques::ataque_validacao_chave::AtaqueValidacaoChave;
use seguranca::ataques::ataque_vetor_deterministico::AtaqueVetorDeterministico;
use seguranca::criptografia_alvo::CriptografiaAlvo;
use seguranca::suite_de_ataques::SuiteDeAtaques;

fn main() {
    let alvo = CriptografiaAlvo::new();

    let mut suite = SuiteDeAtaques::new();
    suite
        .adicionar(Box::new(AtaqueIdaEVolta::new()))
        .adicionar(Box::new(AtaqueAdulteracao::new()))
        .adicionar(Box::new(AtaqueVetorDeterministico))
        .adicionar(Box::new(AtaqueInteroperabilidade))
        .adicionar(Box::new(AtaqueColisaoIV::new()))
        .adicionar(Box::new(AtaqueBytesFixos::new()))
        .adicionar(Box::new(AtaqueChaveErrada::new()))
        .adicionar(Box::new(AtaqueValidacaoChave::new()));

    let passou = suite.rodar_e_imprimir(&alvo);

    if !passou {
        std::process::exit(1);
    }
}

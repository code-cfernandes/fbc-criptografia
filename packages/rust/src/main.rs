//! Runner da suíte de ataques da cifra FBC em Rust.
#![allow(dead_code)]

mod core;
mod seguranca;

use seguranca::ataques::ataque_adulteracao::AtaqueAdulteracao;
use seguranca::ataques::ataque_aproximacao_linear::AtaqueAproximacaoLinear;
use seguranca::ataques::ataque_autocorrelacao::AtaqueAutocorrelacao;
use seguranca::ataques::ataque_avalanche::AtaqueAvalanche;
use seguranca::ataques::ataque_avalanche_chave::AtaqueAvalancheChave;
use seguranca::ataques::ataque_avalanche_checksum::AtaqueAvalancheChecksum;
use seguranca::ataques::ataque_bateria_estatistica::AtaqueBateriaEstatistica;
use seguranca::ataques::ataque_bic::AtaqueBIC;
use seguranca::ataques::ataque_bytes_fixos::AtaqueBytesFixos;
use seguranca::ataques::ataque_canonicalizacao_token::AtaqueCanonicalizacaoToken;
use seguranca::ataques::ataque_chave_errada::AtaqueChaveErrada;
use seguranca::ataques::ataque_chave_relacionada::AtaqueChaveRelacionada;
use seguranca::ataques::ataque_chaves_degeneradas::AtaqueChavesDegeneradas;
use seguranca::ataques::ataque_chaves_fracas::AtaqueChavesFracas;
use seguranca::ataques::ataque_ciphertext_estatistico::AtaqueCiphertextEstatistico;
use seguranca::ataques::ataque_cobertura_dependencia::AtaqueCoberturaDependencia;
use seguranca::ataques::ataque_cobertura_dependencia_iv::AtaqueCoberturaDependenciaIV;
use seguranca::ataques::ataque_colisao_checksum::AtaqueColisaoChecksum;
use seguranca::ataques::ataque_colisao_iv::AtaqueColisaoIV;
use seguranca::ataques::ataque_complexidade_linear::AtaqueComplexidadeLinear;
use seguranca::ataques::ataque_confusao_campos::AtaqueConfusaoCampos;
use seguranca::ataques::ataque_correlacao_mesmo_plaintext::AtaqueCorrelacaoMesmoPlaintext;
use seguranca::ataques::ataque_correlacao_posicoes::AtaqueCorrelacaoPosicoes;
use seguranca::ataques::ataque_cusum::AtaqueCusum;
use seguranca::ataques::ataque_diferencial_keystream::AtaqueDiferencialKeystream;
use seguranca::ataques::ataque_distribuicao_bytes::AtaqueDistribuicaoBytes;
use seguranca::ataques::ataque_distribuicao_por_posicao::AtaqueDistribuicaoPorPosicao;
use seguranca::ataques::ataque_entropia_aproximada::AtaqueEntropiaAproximada;
use seguranca::ataques::ataque_entropia_iv::AtaqueEntropiaIV;
use seguranca::ataques::ataque_fold_estrutural::AtaqueFoldEstrutural;
use seguranca::ataques::ataque_ida_e_volta::AtaqueIdaEVolta;
use seguranca::ataques::ataque_ida_e_volta_binario::AtaqueIdaEVoltaBinario;
use seguranca::ataques::ataque_independencia_proposito::AtaqueIndependenciaProposito;
use seguranca::ataques::ataque_integral::AtaqueIntegral;
use seguranca::ataques::ataque_interoperabilidade::AtaqueInteroperabilidade;
use seguranca::ataques::ataque_ivs_degenerados::AtaqueIVsDegenerados;
use seguranca::ataques::ataque_length_extension::AtaqueLengthExtension;
use seguranca::ataques::ataque_linearidade_checksum::AtaqueLinearidadeChecksum;
use seguranca::ataques::ataque_mac::AtaqueMac;
use seguranca::ataques::ataque_mensagem_longa::AtaqueMensagemLonga;
use seguranca::ataques::ataque_preditor_de_bits::AtaquePreditorDeBits;
use seguranca::ataques::ataque_reuso_iv::AtaqueReusoIV;
use seguranca::ataques::ataque_rotacional::AtaqueRotacional;
use seguranca::ataques::ataque_sac::AtaqueSAC;
use seguranca::ataques::ataque_separacao_chave_iv::AtaqueSeparacaoChaveIV;
use seguranca::ataques::ataque_serial_bits::AtaqueSerialBits;
use seguranca::ataques::ataque_timing::AtaqueTiming;
use seguranca::ataques::ataque_tokens_malformados::AtaqueTokensMalformados;
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
        .adicionar(Box::new(AtaqueColisaoIV::new()))
        .adicionar(Box::new(AtaqueBytesFixos::new()))
        .adicionar(Box::new(AtaqueAvalanche::new()))
        .adicionar(Box::new(AtaqueDistribuicaoBytes::new()))
        .adicionar(Box::new(AtaqueFoldEstrutural::new()))
        .adicionar(Box::new(AtaqueCoberturaDependencia::new()))
        .adicionar(Box::new(AtaqueIVsDegenerados))
        .adicionar(Box::new(AtaqueCorrelacaoMesmoPlaintext::new()))
        .adicionar(Box::new(AtaqueReusoIV))
        .adicionar(Box::new(AtaqueVetorDeterministico))
        .adicionar(Box::new(AtaqueTiming::new()))
        .adicionar(Box::new(AtaqueColisaoChecksum::new()))
        .adicionar(Box::new(AtaqueEntropiaIV::new()))
        .adicionar(Box::new(AtaqueAvalancheChave::new()))
        .adicionar(Box::new(AtaqueAvalancheChecksum::new()))
        .adicionar(Box::new(AtaqueIndependenciaProposito::new()))
        .adicionar(Box::new(AtaqueAutocorrelacao::new()))
        .adicionar(Box::new(AtaqueTokensMalformados))
        .adicionar(Box::new(AtaqueChaveErrada::new()))
        .adicionar(Box::new(AtaqueComplexidadeLinear::new()))
        .adicionar(Box::new(AtaqueBateriaEstatistica::new()))
        .adicionar(Box::new(AtaqueCanonicalizacaoToken))
        .adicionar(Box::new(AtaqueCoberturaDependenciaIV::new()))
        .adicionar(Box::new(AtaqueSeparacaoChaveIV::new()))
        .adicionar(Box::new(AtaqueChavesDegeneradas::new()))
        .adicionar(Box::new(AtaqueSerialBits::new()))
        .adicionar(Box::new(AtaqueCusum::new()))
        .adicionar(Box::new(AtaqueEntropiaAproximada::new()))
        .adicionar(Box::new(AtaqueMensagemLonga::new()))
        .adicionar(Box::new(AtaqueIdaEVoltaBinario::new()))
        .adicionar(Box::new(AtaqueConfusaoCampos))
        .adicionar(Box::new(AtaqueLinearidadeChecksum::new()))
        .adicionar(Box::new(AtaqueValidacaoChave::new()))
        .adicionar(Box::new(AtaqueIntegral::new()))
        .adicionar(Box::new(AtaqueDiferencialKeystream::new()))
        .adicionar(Box::new(AtaqueDistribuicaoPorPosicao::new()))
        .adicionar(Box::new(AtaqueCorrelacaoPosicoes::new()))
        .adicionar(Box::new(AtaquePreditorDeBits::new()))
        .adicionar(Box::new(AtaqueInteroperabilidade))
        .adicionar(Box::new(AtaqueSAC::new()))
        .adicionar(Box::new(AtaqueBIC::new()))
        .adicionar(Box::new(AtaqueChaveRelacionada::new()))
        .adicionar(Box::new(AtaqueRotacional::new()))
        .adicionar(Box::new(AtaqueChavesFracas::new()))
        .adicionar(Box::new(AtaqueAproximacaoLinear::new()))
        .adicionar(Box::new(AtaqueCiphertextEstatistico::new()))
        .adicionar(Box::new(AtaqueMac::new()))
        .adicionar(Box::new(AtaqueLengthExtension::new()));

    let passou = suite.rodar_e_imprimir(&alvo);

    if !passou {
        std::process::exit(1);
    }
}

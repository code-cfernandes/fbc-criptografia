'use strict';

const CriptografiaAlvo = require('../src/Seguranca/CriptografiaAlvo.js');
const SuiteDeAtaques = require('../src/Seguranca/SuiteDeAtaques.js');

const AtaqueIdaEVolta = require('../src/Seguranca/Ataques/AtaqueIdaEVolta.js');
const AtaqueAdulteracao = require('../src/Seguranca/Ataques/AtaqueAdulteracao.js');
const AtaqueColisaoIV = require('../src/Seguranca/Ataques/AtaqueColisaoIV.js');
const AtaqueBytesFixos = require('../src/Seguranca/Ataques/AtaqueBytesFixos.js');
const AtaqueAvalanche = require('../src/Seguranca/Ataques/AtaqueAvalanche.js');
const AtaqueDistribuicaoBytes = require('../src/Seguranca/Ataques/AtaqueDistribuicaoBytes.js');
const AtaqueFoldEstrutural = require('../src/Seguranca/Ataques/AtaqueFoldEstrutural.js');
const AtaqueCoberturaDependencia = require('../src/Seguranca/Ataques/AtaqueCoberturaDependencia.js');
const AtaqueIVsDegenerados = require('../src/Seguranca/Ataques/AtaqueIVsDegenerados.js');
const AtaqueCorrelacaoMesmoPlaintext = require('../src/Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.js');
const AtaqueReusoIV = require('../src/Seguranca/Ataques/AtaqueReusoIV.js');
const AtaqueVetorDeterministico = require('../src/Seguranca/Ataques/AtaqueVetorDeterministico.js');
const AtaqueTiming = require('../src/Seguranca/Ataques/AtaqueTiming.js');
const AtaqueColisaoChecksum = require('../src/Seguranca/Ataques/AtaqueColisaoChecksum.js');
const AtaqueEntropiaIV = require('../src/Seguranca/Ataques/AtaqueEntropiaIV.js');
const AtaqueAvalancheChave = require('../src/Seguranca/Ataques/AtaqueAvalancheChave.js');
const AtaqueAvalancheChecksum = require('../src/Seguranca/Ataques/AtaqueAvalancheChecksum.js');
const AtaqueIndependenciaProposito = require('../src/Seguranca/Ataques/AtaqueIndependenciaProposito.js');
const AtaqueAutocorrelacao = require('../src/Seguranca/Ataques/AtaqueAutocorrelacao.js');
const AtaqueTokensMalformados = require('../src/Seguranca/Ataques/AtaqueTokensMalformados.js');
const AtaqueChaveErrada = require('../src/Seguranca/Ataques/AtaqueChaveErrada.js');
const AtaqueComplexidadeLinear = require('../src/Seguranca/Ataques/AtaqueComplexidadeLinear.js');
const AtaqueBateriaEstatistica = require('../src/Seguranca/Ataques/AtaqueBateriaEstatistica.js');
const AtaqueCanonicalizacaoToken = require('../src/Seguranca/Ataques/AtaqueCanonicalizacaoToken.js');
const AtaqueCoberturaDependenciaIV = require('../src/Seguranca/Ataques/AtaqueCoberturaDependenciaIV.js');
const AtaqueSeparacaoChaveIV = require('../src/Seguranca/Ataques/AtaqueSeparacaoChaveIV.js');
const AtaqueChavesDegeneradas = require('../src/Seguranca/Ataques/AtaqueChavesDegeneradas.js');
const AtaqueSerialBits = require('../src/Seguranca/Ataques/AtaqueSerialBits.js');
const AtaqueCusum = require('../src/Seguranca/Ataques/AtaqueCusum.js');
const AtaqueEntropiaAproximada = require('../src/Seguranca/Ataques/AtaqueEntropiaAproximada.js');
const AtaqueMensagemLonga = require('../src/Seguranca/Ataques/AtaqueMensagemLonga.js');
const AtaqueIdaEVoltaBinario = require('../src/Seguranca/Ataques/AtaqueIdaEVoltaBinario.js');
const AtaqueConfusaoCampos = require('../src/Seguranca/Ataques/AtaqueConfusaoCampos.js');
const AtaqueLinearidadeChecksum = require('../src/Seguranca/Ataques/AtaqueLinearidadeChecksum.js');
const AtaqueValidacaoChave = require('../src/Seguranca/Ataques/AtaqueValidacaoChave.js');
const AtaqueIntegral = require('../src/Seguranca/Ataques/AtaqueIntegral.js');
const AtaqueDiferencialKeystream = require('../src/Seguranca/Ataques/AtaqueDiferencialKeystream.js');
const AtaqueDistribuicaoPorPosicao = require('../src/Seguranca/Ataques/AtaqueDistribuicaoPorPosicao.js');
const AtaqueCorrelacaoPosicoes = require('../src/Seguranca/Ataques/AtaqueCorrelacaoPosicoes.js');
const AtaquePreditorDeBits = require('../src/Seguranca/Ataques/AtaquePreditorDeBits.js');

const alvo = new CriptografiaAlvo();

const suite = new SuiteDeAtaques();
suite
  .adicionar(new AtaqueIdaEVolta())
  .adicionar(new AtaqueAdulteracao())
  .adicionar(new AtaqueColisaoIV())
  .adicionar(new AtaqueBytesFixos())
  .adicionar(new AtaqueAvalanche())
  .adicionar(new AtaqueDistribuicaoBytes())
  .adicionar(new AtaqueFoldEstrutural())
  .adicionar(new AtaqueCoberturaDependencia())
  .adicionar(new AtaqueIVsDegenerados())
  .adicionar(new AtaqueCorrelacaoMesmoPlaintext())
  .adicionar(new AtaqueReusoIV())
  .adicionar(new AtaqueVetorDeterministico())
  .adicionar(new AtaqueTiming())
  .adicionar(new AtaqueColisaoChecksum())
  .adicionar(new AtaqueEntropiaIV())
  .adicionar(new AtaqueAvalancheChave())
  .adicionar(new AtaqueAvalancheChecksum())
  .adicionar(new AtaqueIndependenciaProposito())
  .adicionar(new AtaqueAutocorrelacao())
  .adicionar(new AtaqueTokensMalformados())
  .adicionar(new AtaqueChaveErrada())
  .adicionar(new AtaqueComplexidadeLinear())
  .adicionar(new AtaqueBateriaEstatistica())
  .adicionar(new AtaqueCanonicalizacaoToken())
  .adicionar(new AtaqueCoberturaDependenciaIV())
  .adicionar(new AtaqueSeparacaoChaveIV())
  .adicionar(new AtaqueChavesDegeneradas())
  .adicionar(new AtaqueSerialBits())
  .adicionar(new AtaqueCusum())
  .adicionar(new AtaqueEntropiaAproximada())
  .adicionar(new AtaqueMensagemLonga())
  .adicionar(new AtaqueIdaEVoltaBinario())
  .adicionar(new AtaqueConfusaoCampos())
  .adicionar(new AtaqueLinearidadeChecksum())
  .adicionar(new AtaqueValidacaoChave())
  .adicionar(new AtaqueIntegral())
  .adicionar(new AtaqueDiferencialKeystream())
  .adicionar(new AtaqueDistribuicaoPorPosicao())
  .adicionar(new AtaqueCorrelacaoPosicoes())
  .adicionar(new AtaquePreditorDeBits());

const passou = suite.rodarEImprimir(alvo);

process.exit(passou ? 0 : 1);

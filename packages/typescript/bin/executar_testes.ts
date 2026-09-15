import { CriptografiaAlvo } from '../src/Seguranca/CriptografiaAlvo.ts';
import { SuiteDeAtaques } from '../src/Seguranca/SuiteDeAtaques.ts';

import { AtaqueIdaEVolta } from '../src/Seguranca/Ataques/AtaqueIdaEVolta.ts';
import { AtaqueAdulteracao } from '../src/Seguranca/Ataques/AtaqueAdulteracao.ts';
import { AtaqueColisaoIV } from '../src/Seguranca/Ataques/AtaqueColisaoIV.ts';
import { AtaqueBytesFixos } from '../src/Seguranca/Ataques/AtaqueBytesFixos.ts';
import { AtaqueAvalanche } from '../src/Seguranca/Ataques/AtaqueAvalanche.ts';
import { AtaqueDistribuicaoBytes } from '../src/Seguranca/Ataques/AtaqueDistribuicaoBytes.ts';
import { AtaqueFoldEstrutural } from '../src/Seguranca/Ataques/AtaqueFoldEstrutural.ts';
import { AtaqueCoberturaDependencia } from '../src/Seguranca/Ataques/AtaqueCoberturaDependencia.ts';
import { AtaqueIVsDegenerados } from '../src/Seguranca/Ataques/AtaqueIVsDegenerados.ts';
import { AtaqueCorrelacaoMesmoPlaintext } from '../src/Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.ts';
import { AtaqueReusoIV } from '../src/Seguranca/Ataques/AtaqueReusoIV.ts';
import { AtaqueVetorDeterministico } from '../src/Seguranca/Ataques/AtaqueVetorDeterministico.ts';
import { AtaqueTiming } from '../src/Seguranca/Ataques/AtaqueTiming.ts';
import { AtaqueColisaoChecksum } from '../src/Seguranca/Ataques/AtaqueColisaoChecksum.ts';
import { AtaqueEntropiaIV } from '../src/Seguranca/Ataques/AtaqueEntropiaIV.ts';
import { AtaqueAvalancheChave } from '../src/Seguranca/Ataques/AtaqueAvalancheChave.ts';
import { AtaqueAvalancheChecksum } from '../src/Seguranca/Ataques/AtaqueAvalancheChecksum.ts';
import { AtaqueIndependenciaProposito } from '../src/Seguranca/Ataques/AtaqueIndependenciaProposito.ts';
import { AtaqueAutocorrelacao } from '../src/Seguranca/Ataques/AtaqueAutocorrelacao.ts';
import { AtaqueTokensMalformados } from '../src/Seguranca/Ataques/AtaqueTokensMalformados.ts';
import { AtaqueChaveErrada } from '../src/Seguranca/Ataques/AtaqueChaveErrada.ts';
import { AtaqueComplexidadeLinear } from '../src/Seguranca/Ataques/AtaqueComplexidadeLinear.ts';
import { AtaqueBateriaEstatistica } from '../src/Seguranca/Ataques/AtaqueBateriaEstatistica.ts';
import { AtaqueCanonicalizacaoToken } from '../src/Seguranca/Ataques/AtaqueCanonicalizacaoToken.ts';
import { AtaqueCoberturaDependenciaIV } from '../src/Seguranca/Ataques/AtaqueCoberturaDependenciaIV.ts';
import { AtaqueSeparacaoChaveIV } from '../src/Seguranca/Ataques/AtaqueSeparacaoChaveIV.ts';
import { AtaqueChavesDegeneradas } from '../src/Seguranca/Ataques/AtaqueChavesDegeneradas.ts';
import { AtaqueSerialBits } from '../src/Seguranca/Ataques/AtaqueSerialBits.ts';
import { AtaqueCusum } from '../src/Seguranca/Ataques/AtaqueCusum.ts';
import { AtaqueEntropiaAproximada } from '../src/Seguranca/Ataques/AtaqueEntropiaAproximada.ts';
import { AtaqueMensagemLonga } from '../src/Seguranca/Ataques/AtaqueMensagemLonga.ts';
import { AtaqueIdaEVoltaBinario } from '../src/Seguranca/Ataques/AtaqueIdaEVoltaBinario.ts';
import { AtaqueConfusaoCampos } from '../src/Seguranca/Ataques/AtaqueConfusaoCampos.ts';
import { AtaqueLinearidadeChecksum } from '../src/Seguranca/Ataques/AtaqueLinearidadeChecksum.ts';
import { AtaqueValidacaoChave } from '../src/Seguranca/Ataques/AtaqueValidacaoChave.ts';
import { AtaqueIntegral } from '../src/Seguranca/Ataques/AtaqueIntegral.ts';
import { AtaqueDiferencialKeystream } from '../src/Seguranca/Ataques/AtaqueDiferencialKeystream.ts';
import { AtaqueDistribuicaoPorPosicao } from '../src/Seguranca/Ataques/AtaqueDistribuicaoPorPosicao.ts';
import { AtaqueCorrelacaoPosicoes } from '../src/Seguranca/Ataques/AtaqueCorrelacaoPosicoes.ts';
import { AtaquePreditorDeBits } from '../src/Seguranca/Ataques/AtaquePreditorDeBits.ts';

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

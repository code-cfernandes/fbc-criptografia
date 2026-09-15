'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');
const { randomBytes } = require('../Util.js');

/**
 * Esse é o ataque que pegou o bug mais sério que encontramos: quando a
 * distância de mistura era exatamente metade do bloco, TODOS os IVs
 * aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
 * Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
 */
class AtaqueFoldEstrutural {
  constructor({ amostras = 5000, tamanhoBloco = 32 } = {}) {
    this.amostras = amostras;
    this.tamanhoBloco = tamanhoBloco;
  }

  nome() {
    return 'Fold estrutural (metades/quartos/oitavos repetidos)';
  }

  executar(alvo) {
    const chave = alvo.chaveDeTeste();
    const primeiro = alvo.gerarKeystreamBruto(
      chave,
      randomBytes(alvo.tamanhoIv()),
      'enc',
      this.tamanhoBloco,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const divisores = [2, 4, 8, 16].filter(
      (d) => this.tamanhoBloco % d === 0 && this.tamanhoBloco / d >= 1,
    );
    const ocorrencias = {};
    for (const d of divisores) {
      ocorrencias[d] = 0;
    }

    // Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
    // a chance de colisão por acaso é ~1/256^tam por par comparado -
    // desprezível para tam >= 2, então qualquer contagem > 0 já é
    // suspeita o bastante pra investigar (ajustamos a margem pra
    // fatias de 1-2 bytes, onde colisão por acaso é mais provável).
    for (let i = 0; i < this.amostras; i++) {
      const ks = alvo.gerarKeystreamBruto(
        chave,
        randomBytes(alvo.tamanhoIv()),
        'enc',
        this.tamanhoBloco,
      );
      for (const divisor of divisores) {
        const tamFatia = Math.trunc(this.tamanhoBloco / divisor);
        const primeiraFatia = ks.subarray(0, tamFatia);
        for (let j = 1; j < divisor; j++) {
          if (ks.subarray(j * tamFatia, j * tamFatia + tamFatia).equals(primeiraFatia)) {
            ocorrencias[divisor]++;
            break;
          }
        }
      }
    }

    const margem = (divisor) =>
      this.tamanhoBloco / divisor <= 2 ? Math.trunc(this.amostras * 0.01) + 3 : 5;

    const problemas = {};
    for (const divisor of divisores) {
      const c = ocorrencias[divisor];
      if (c > margem(divisor)) {
        problemas[divisor] = c;
      }
    }

    if (Object.keys(problemas).length > 0) {
      const detalhe = Object.keys(problemas)
        .map((d) => `1/${d} do bloco repetido em ${problemas[d]}/${this.amostras}`)
        .join(', ');
      return new ResultadoAtaque(this.nome(), true, 'critica', detalhe, {
        ocorrencias,
      });
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      'Nenhuma repetição estrutural acima do ruído esperado: ' + JSON.stringify(ocorrencias),
    );
  }
}

module.exports = AtaqueFoldEstrutural;

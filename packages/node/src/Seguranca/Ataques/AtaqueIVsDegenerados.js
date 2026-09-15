'use strict';

const ResultadoAtaque = require('../ResultadoAtaque.js');
const SkipAtaqueException = require('../SkipAtaqueException.js');

/**
 * Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
 * (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
 * mesmo quando a maioria das entradas se comporta bem. Testa especificamente
 * esses casos extremos, que testes com entrada aleatória raramente cobrem.
 */
class AtaqueIVsDegenerados {
  nome() {
    return 'IVs degenerados (zero, 0xFF, alternado)';
  }

  executar(alvo) {
    const chave = alvo.chaveDeTeste();
    const tamanhoIv = alvo.tamanhoIv();
    const tamanhoBloco = 32;

    const primeiro = alvo.gerarKeystreamBruto(
      chave,
      Buffer.alloc(tamanhoIv, 0),
      'enc',
      tamanhoBloco,
    );
    if (primeiro == null) {
      throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
    }

    const casos = {
      zero: Buffer.alloc(tamanhoIv, 0x00),
      '0xFF': Buffer.alloc(tamanhoIv, 0xff),
      'alternado 0xAA': Buffer.alloc(tamanhoIv, 0xaa),
      'alternado 0x55': Buffer.alloc(tamanhoIv, 0x55),
      crescente: Buffer.from(Array.from({ length: tamanhoIv }, (_, i) => i)),
    };

    const problemas = {};
    for (const nome of Object.keys(casos)) {
      const ks = alvo.gerarKeystreamBruto(chave, casos[nome], 'enc', tamanhoBloco);

      const metade = Math.trunc(tamanhoBloco / 2);
      const periodico = ks.subarray(0, metade).equals(ks.subarray(metade, metade + metade));

      const bytesUnicos = new Set(ks).size;
      const poucaVariedade = bytesUnicos < tamanhoBloco * 0.5;

      if (periodico || poucaVariedade) {
        problemas[nome] = { periodico, bytesUnicos };
      }
    }

    if (Object.keys(problemas).length > 0) {
      const detalhe = Object.keys(problemas)
        .map(
          (nome) =>
            `${nome} (periódico=${
              problemas[nome].periodico ? 'sim' : 'não'
            }, bytes únicos=${problemas[nome].bytesUnicos}/${tamanhoBloco})`,
        )
        .join('; ');
      return new ResultadoAtaque(this.nome(), true, 'alta', detalhe, problemas);
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      'Nenhum dos ' +
        Object.keys(casos).length +
        ' IVs degenerados testados produziu saída anômala',
    );
  }
}

module.exports = AtaqueIVsDegenerados;

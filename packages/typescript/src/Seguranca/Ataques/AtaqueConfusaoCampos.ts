import type { AlvoCriptografico } from '../AlvoCriptografico.ts';
import type { AtaqueInterface } from '../AtaqueInterface.ts';
import { CriptografiaAlvo } from '../CriptografiaAlvo.ts';
import { ResultadoAtaque } from '../ResultadoAtaque.ts';
import { SkipAtaqueException } from '../SkipAtaqueException.ts';

/**
 * O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
 * ambíguo, um atacante pode reordenar/deslocar os campos e construir um
 * token que sistemas diferentes interpretam de formas diferentes. Todos os
 * rearranjos devem ser rejeitados pela integridade.
 */
export class AtaqueConfusaoCampos implements AtaqueInterface {
  nome(): string {
    return 'Confusão de campos do token (reordenação/deslocamento)';
  }

  executar(alvo: AlvoCriptografico): ResultadoAtaque {
    if (!(alvo instanceof CriptografiaAlvo)) {
      throw new SkipAtaqueException('Precisa de base64url_encode/decode do alvo.');
    }

    const texto = 'MENSAGEM_PARA_TESTE_DE_CAMPOS';
    const token = alvo.encrypt(texto);
    const prefixo = alvo.prefixo();
    const campos = alvo.decompor(alvo.base64urlDecode(token.slice(prefixo.length)));

    const integridade = campos.integridade;
    const ciphertext = campos.ciphertext;
    const iv = campos.iv;

    const variantes: Record<string, Buffer> = {
      'iv no início': Buffer.concat([iv, integridade, ciphertext]),
      'ciphertext antes da integridade': Buffer.concat([ciphertext, integridade, iv]),
      'iv duplicado no fim': Buffer.concat([integridade, ciphertext, iv, iv]),
      'integridade encurtada': Buffer.concat([integridade.subarray(1), ciphertext, iv]),
      'byte extra no início': Buffer.concat([Buffer.from('X'), integridade, ciphertext, iv]),
      'byte extra entre integridade e ciphertext': Buffer.concat([
        integridade,
        Buffer.from('X'),
        ciphertext,
        iv,
      ]),
      'byte extra antes do iv': Buffer.concat([integridade, ciphertext, Buffer.from('X'), iv]),
      'iv rotacionado': Buffer.concat([integridade, ciphertext, Buffer.from(iv).reverse()]),
      'iv e último byte do ciphertext trocados': Buffer.concat([
        integridade,
        ciphertext.subarray(0, ciphertext.length - 1),
        iv,
        ciphertext.subarray(ciphertext.length - 1),
      ]),
    };

    const aceitas: string[] = [];
    for (const nome of Object.keys(variantes)) {
      const bruto = variantes[nome];
      const tokenVariante = prefixo + alvo.base64urlEncode(bruto);
      try {
        const r = alvo.decrypt(tokenVariante);
        aceitas.push(`${nome} -> aceito (retornou ${Buffer.byteLength(r, 'utf8')} bytes)`);
      } catch (e) {
        // esperado
      }
    }

    if (aceitas.length > 0) {
      return new ResultadoAtaque(
        this.nome(),
        true,
        'critica',
        `${aceitas.length} rearranjo(s) de campo foram aceitos`,
        { exemplos: aceitas },
      );
    }

    return new ResultadoAtaque(
      this.nome(),
      false,
      'info',
      `Todos os ${Object.keys(variantes).length} rearranjos de campo foram rejeitados`,
    );
  }
}

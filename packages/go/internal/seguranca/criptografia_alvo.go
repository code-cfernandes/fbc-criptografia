package seguranca

import (
	"os"

	"criptografia/internal/core"
)

// ChavePadrao é a chave de teste usada por padrão nos ataques.
const ChavePadrao = "pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf"

// CriptografiaAlvo liga a suíte de ataques à cifra real, expondo as camadas
// internas de keystream e checksum.
type CriptografiaAlvo struct {
	chaveTeste string
}

// NovoCriptografiaAlvo cria um alvo e escreve a chave no ambiente do processo.
// Sem argumentos, usa ChavePadrao.
func NovoCriptografiaAlvo(chaveTeste ...string) *CriptografiaAlvo {
	chave := ChavePadrao
	if len(chaveTeste) > 0 {
		chave = chaveTeste[0]
	}
	os.Setenv("FBC_KEY", chave)
	return &CriptografiaAlvo{chaveTeste: chave}
}

// Encrypt cifra o texto.
func (c *CriptografiaAlvo) Encrypt(texto []byte) (string, error) {
	return core.Encrypt(texto)
}

// Decrypt decifra o token.
func (c *CriptografiaAlvo) Decrypt(token string) (string, error) {
	return core.Decrypt(token)
}

// Prefixo devolve o prefixo do token.
func (c *CriptografiaAlvo) Prefixo() string {
	return "FBC"
}

// Decompor separa um token decodificado nos seus campos.
func (c *CriptografiaAlvo) Decompor(tokenDecodificado []byte) CamposToken {
	n := len(tokenDecodificado)
	tamIv := c.TamanhoIv()

	if n < 32+tamIv {
		integridade := tokenDecodificado
		if n > 32 {
			integridade = tokenDecodificado[:32]
		}
		iv := []byte{}
		if n >= tamIv {
			iv = tokenDecodificado[n-tamIv:]
		}
		return CamposToken{Integridade: integridade, Ciphertext: []byte{}, IV: iv}
	}

	return CamposToken{
		Integridade: tokenDecodificado[:32],
		Ciphertext:  tokenDecodificado[32 : n-tamIv],
		IV:          tokenDecodificado[n-tamIv:],
	}
}

// Recompor junta os campos em um token decodificado.
func (c *CriptografiaAlvo) Recompor(campos CamposToken) []byte {
	out := make([]byte, 0, len(campos.Integridade)+len(campos.Ciphertext)+len(campos.IV))
	out = append(out, campos.Integridade...)
	out = append(out, campos.Ciphertext...)
	out = append(out, campos.IV...)
	return out
}

// GerarKeystreamBruto expõe o gerador de keystream interno.
func (c *CriptografiaAlvo) GerarKeystreamBruto(key, iv []byte, proposito string, tamanho int) []byte {
	return core.GerarKeystream(key, iv, proposito, tamanho)
}

// ChecksumBruto expõe o checksum interno.
func (c *CriptografiaAlvo) ChecksumBruto(dados, key []byte) []byte {
	return core.Checksum(dados, key)
}

// ChaveDeTeste devolve a chave de teste do alvo.
func (c *CriptografiaAlvo) ChaveDeTeste() string {
	return c.chaveTeste
}

// TamanhoIv devolve o tamanho do IV em bytes.
func (c *CriptografiaAlvo) TamanhoIv() int {
	return 16
}

// Base64urlEncode codifica em base64url.
func (c *CriptografiaAlvo) Base64urlEncode(data []byte) string {
	return core.Base64urlEncode(data)
}

// Base64urlDecode decodifica base64url.
func (c *CriptografiaAlvo) Base64urlDecode(data string) ([]byte, error) {
	return core.Base64urlDecode(data)
}

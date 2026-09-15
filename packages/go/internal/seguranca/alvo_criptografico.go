package seguranca

// CamposToken são os campos que compõem um token já decodificado do base64url.
type CamposToken struct {
	Integridade []byte
	Ciphertext  []byte
	IV          []byte
}

// AlvoCriptografico é o contrato que uma cifra precisa cumprir para ser testada
// pela suíte de ataques.
//
// Os métodos obrigatórios (Encrypt/Decrypt) bastam para os ataques de alto nível.
// GerarKeystreamBruto e ChecksumBruto expõem as camadas internas para os ataques
// de baixo nível.
type AlvoCriptografico interface {
	Encrypt(texto []byte) (string, error)

	Decrypt(token string) (string, error)

	// Prefixo esperado no início de um token válido (ex: "FBC").
	Prefixo() string

	// Decompor decompõe um token (sem prefixo e já base64url-decodificado).
	Decompor(tokenDecodificado []byte) CamposToken

	// Recompor recompõe um token a partir dos campos (inverso de Decompor).
	Recompor(campos CamposToken) []byte

	// GerarKeystreamBruto gera N bytes de keystream bruto a partir de key+iv+propósito.
	GerarKeystreamBruto(key, iv []byte, proposito string, tamanho int) []byte

	// ChecksumBruto chama o Checksum interno diretamente.
	ChecksumBruto(dados, key []byte) []byte

	// ChaveDeTeste devolve uma chave válida para usar nos testes.
	ChaveDeTeste() string

	// TamanhoIv devolve o tamanho do IV em bytes.
	TamanhoIv() int

	Base64urlEncode(data []byte) string

	Base64urlDecode(data string) ([]byte, error)
}

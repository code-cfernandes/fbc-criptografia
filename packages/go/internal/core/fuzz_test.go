package core

import (
	"os"
	"testing"
)

// FuzzDecrypt alimenta bytes arbitrários no decodificador de token. A função
// devolve erro para entrada inválida e nunca deve entrar em panic.
//
// IMPORTANTE: sem FBC_KEY definida no ambiente, TODA entrada que começa com
// "FBC" falha imediatamente na checagem de tamanho de chave, antes mesmo de
// tocar em base64/checksum/parsing de campos - o fuzzer nunca exercitaria a
// lógica que interessa. Por isso o teste fixa a chave sozinho, sem depender
// do ambiente onde roda (scripts/fuzz-memoria.sh também exporta, redundância
// intencional para quem rodar o teste isoladamente).
//
//	go test ./internal/core -run=^$ -fuzz=FuzzDecrypt -fuzztime=5m
func FuzzDecrypt(f *testing.F) {
	os.Setenv("FBC_KEY", "chave-fixa-de-32-bytes-p-fuzz!!0")

	for _, semente := range []string{
		"",
		"FBC",
		"FBCAAAA",
		"FBC!@#$",
		"nao-comeca-com-fbc",
		"FBC////////",
		"FBC________________",
		// Token real e válido (mesma chave fixa acima) - dá ao fuzzer um
		// ponto de partida que já passa por prefixo, chave, base64 e
		// integridade, para que a mutação explore de fato o parsing interno.
		"FBC1feA4sFFTbRJiUcS9f0kw2If5KTSoAno5ZeYkHPzPuywsaP4bV3JmG-Z4Lksg6CIgSg_QlhdcXS9KyJbRpUTKoOmS9RDj2llcguVdtCPU9g",
	} {
		f.Add(semente)
	}

	f.Fuzz(func(t *testing.T, token string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic com entrada %q: %v", token, r)
			}
		}()
		_, _ = Decrypt(token)
	})
}

package core

import "testing"

// FuzzDecrypt alimenta bytes arbitrários no decodificador de token. A função
// devolve erro para entrada inválida e nunca deve entrar em panic.
//
//	go test ./internal/core -run=^$ -fuzz=FuzzDecrypt -fuzztime=5m
func FuzzDecrypt(f *testing.F) {
	for _, semente := range []string{
		"",
		"FBC",
		"FBCAAAA",
		"FBC!@#$",
		"nao-comeca-com-fbc",
		"FBC////////",
		"FBC________________",
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

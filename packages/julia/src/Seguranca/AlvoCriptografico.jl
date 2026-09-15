"""
Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.

Os métodos `encrypt`/`decrypt` bastam pros ataques de alto nível (ida-e-volta,
adulteração, colisão de IV, bytes fixos entre tokens). `gerar_keystream_bruto`
e `checksum_bruto` expõem as camadas internas para os ataques de baixo nível.
"""
abstract type AlvoCriptografico end

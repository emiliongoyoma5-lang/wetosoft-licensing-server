# WetoSoft Licensing Server

Servidor central de licenciamento do WetoSoft. O cliente WetoSoft continua local-first/offline-first; este serviço controla ativação, estado das licenças, instalações e assinatura criptográfica dos tokens.

## Arquitetura inicial de baixo custo

- Netlify Functions para a API.
- PostgreSQL compatível com Neon Free para dados centrais.
- Painel administrativo separado em `admin/`.
- Chave privada Ed25519 somente no servidor.
- Chave pública distribuída no cliente WetoSoft.

## Variáveis de ambiente

Copie `.env.example` para o ambiente de deploy e preencha:

- `DATABASE_URL`
- `LICENSE_PRIVATE_JWK_JSON`
- `LICENSE_PUBLIC_JWK_JSON`
- `ADMIN_API_KEY_SHA256`
- `LICENSE_ISSUER`
- `LICENSE_AUDIENCE`

Nunca coloque a chave privada no Git ou no PWA.

## Banco

Execute `migrations/001_initial.sql` no PostgreSQL.

## Chave de assinatura

Execute:

`npm run generate-key`

Guarde a chave privada apenas como secret no servidor. A chave pública será incorporada ao cliente WetoSoft em uma etapa posterior.

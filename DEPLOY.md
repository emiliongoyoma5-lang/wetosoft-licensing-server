# Deploy inicial — WetoSoft Licensing

## 1. PostgreSQL

Criar um projeto PostgreSQL gratuito no Neon e obter `DATABASE_URL` com SSL.

Executar `migrations/001_initial.sql` uma vez.

## 2. Chaves

Localmente:

```bash
npm install
npm run generate-key
```

Guardar `LICENSE_PRIVATE_JWK_JSON` exclusivamente como secret no Netlify.
A chave pública (`LICENSE_PUBLIC_JWK_JSON`) será incorporada no cliente WetoSoft depois da validação do servidor.

## 3. Chave administrativa

Gerar uma chave longa aleatória fora do navegador e guardar somente o SHA-256 em `ADMIN_API_KEY_SHA256`.

Exemplo local:

```bash
node -e "const c=require('crypto'); const k=c.randomBytes(32).toString('base64url'); console.log(k); console.log(c.createHash('sha256').update(k).digest('hex'))"
```

A chave em texto é usada apenas pelo administrador; o servidor recebe-a pelo header `Authorization: Bearer ...` e compara o hash.

## 4. Netlify

Conectar o repositório ao Netlify. O `netlify.toml` já define:

- publicação do painel `admin/`;
- Functions em `netlify/functions`;
- rota `/api/v1/*` para a Function `api`.

Configurar as variáveis:

- `DATABASE_URL`
- `LICENSE_PRIVATE_JWK_JSON`
- `LICENSE_PUBLIC_JWK_JSON`
- `ADMIN_API_KEY_SHA256`
- `LICENSE_ISSUER`
- `LICENSE_AUDIENCE`

## 5. Primeira validação

1. Criar tenant diretamente no PostgreSQL.
2. Criar/usar um plano.
3. Chamar `POST /api/v1/admin/activation-code` com a chave administrativa.
4. Guardar o código devolvido uma única vez.
5. Chamar `POST /api/v1/activation` com código + `installationId`.
6. Verificar que o token JWS foi emitido.
7. Repetir a ativação com o mesmo código e confirmar `409 ACTIVATION_CODE_ALREADY_USED`.
8. Testar `/license/status` e `/license/refresh`.
9. Revogar a licença e confirmar que o refresh deixa de funcionar.

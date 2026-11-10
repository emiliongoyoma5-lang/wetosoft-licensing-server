# WetoSoft Licensing Server — v1.8.0 (consolidated test package)

Backend de licenciamento e painel administrativo do WetoSoft, preparado para validação num ambiente de testes Netlify + Neon.

## Conteúdo

- `netlify/functions/api.mjs`: API de autenticação administrativa, bootstrap, gestão de administradores, empresas, licenças e activações.
- `netlify/functions/auth.mjs`: tokens de sessão, hashing Scrypt e verificação de passwords.
- `public/index.html`: painel administrativo publicado na raiz do site.
- `netlify.toml`: publica exclusivamente `public/`; o código das funções, migrations e scripts não fica na raiz pública.
- `tests/`: testes unitários e verificações estáticas de contratos de segurança.
- `migrations/001_admin_hierarchy.sql`: migration histórica da hierarquia; ver `migrations/README.md` antes de qualquer execução.

## Estado desta versão

Esta é uma consolidação local baseada no pacote integral de 31/10 e nas correcções administrativas v1.7, mantendo as protecções posteriores da API de activação e revogação. Não foi publicada no GitHub nem no Netlify.

## Requisitos

- Node.js 24 ou superior.
- Netlify Functions (Node 24).
- Neon PostgreSQL com o schema compatível com o ambiente de teste.

## Desenvolvimento e testes

```bash
npm test
npm run lint:syntax
```

O conjunto actual contém testes unitários de hashing e testes estáticos de contratos/estrutura. Não substitui testes HTTP reais nem integração PostgreSQL.

## Configuração

Copiar `.env.example` para `.env` apenas em ambiente local e preencher com credenciais de TESTE. No Netlify, configurar as variáveis descritas em `DEPLOY.md` no site de testes. Nunca usar a `DATABASE_URL` de produção.

## Bootstrap do administrador principal

O primeiro administrador é criado pelo endpoint de bootstrap, protegido por `ADMIN_BOOTSTRAP_SECRET` e pelo estado de utilização única em `admin_bootstrap`. A criação do `SUPER_ADMIN_PRINCIPAL` não é automática. Só executar quando o responsável autorizar expressamente e estiver a usar o site de testes e a branch Neon de teste.

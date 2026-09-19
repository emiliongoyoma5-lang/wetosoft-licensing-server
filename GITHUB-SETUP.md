# WetoSoft Licensing Server — GitHub setup

This repository is prepared for deployment to Netlify.

## 1. Create the repository

Create a new **private** GitHub repository named:

`wetosoft-licensing-server`

Do not add a README, `.gitignore`, or license from GitHub because those files are already included here.

## 2. Upload this directory

Upload the contents of this directory to the repository root.

The repository must contain:

- `netlify/functions/`
- `migrations/`
- `admin/`
- `scripts/`
- `tests/`
- `netlify.toml`
- `package.json`
- `.env.example`

## 3. Secrets

Never commit `.env` or real credentials.

Configure these later in Netlify Environment Variables:

- `DATABASE_URL` — Neon PostgreSQL connection string
- `LICENSE_PRIVATE_JWK_JSON` — server-only Ed25519 private JWK
- `LICENSE_ISSUER` — public issuer URL
- `LICENSE_AUDIENCE` — `wetosoft-client`
- `SESSION_SECRET` — reserved for future session hardening
- `ADMIN_BOOTSTRAP_SECRET` — used only during controlled bootstrap
- `ALLOWED_ORIGINS` — optional comma-separated browser origins when the client is hosted separately

## 4. Database

Run these migrations in Neon, in order:

1. `migrations/001_initial.sql`
2. `migrations/002_admin_access.sql`

## 5. Local verification

Use Node.js 24 LTS.

```bash
npm install
npm test
npm run lint:syntax
```

Expected current static test result: 4 tests passing and 7 JavaScript files syntactically valid.

# Preparação de deploy — ambiente de TESTE

> Este documento não autoriza nem executa deploy. O pacote actual está preparado localmente; ainda falta configurar segredos e publicar manualmente no site de teste.

## Destino permitido

- Netlify site: `wetosoft-licensing-test`
- URL: `https://wetosoft-licensing-test.netlify.app`
- Site ID: `6d1aca73-ff27-4962-b51f-0d42884ba2c6`
- Neon project: `wandering-mode-88186149`
- Neon branch: `br-summer-bird-zayl0nyj`
- Database: `neondb`

**Não utilizar** o site `wetosoft-licensing-server.netlify.app` nem a branch Neon de produção.

## Variáveis Netlify necessárias

Configurar no site de teste, para o contexto Production desse site de teste (e também Deploy Previews se forem usados):

| Variável | Valor |
|---|---|
| `DATABASE_URL` | Connection string da branch Neon de teste `br-summer-bird-zayl0nyj`, base `neondb` |
| `LICENSE_PRIVATE_JWK_JSON` | JWK privado Ed25519 gerado especificamente para teste |
| `LICENSE_ISSUER` | `urn:wetosoft:licensing-server` |
| `LICENSE_AUDIENCE` | `urn:wetosoft:client` |
| `ADMIN_BOOTSTRAP_SECRET` | Segredo aleatório forte, temporário, só para o primeiro bootstrap |

Marcar `DATABASE_URL`, `LICENSE_PRIVATE_JWK_JSON` e `ADMIN_BOOTSTRAP_SECRET` como secrets. Não colocar valores em commits, ZIPs partilhados ou mensagens.

## Ordem segura

1. Confirmar visualmente o site e o ID acima antes de qualquer alteração.
2. Configurar as variáveis exclusivamente no site de teste.
3. Publicar o conteúdo deste ZIP no site de teste usando deploy manual compatível com Netlify. O `netlify.toml` define `public/` como publicação estática e `netlify/functions` como funções.
4. Confirmar que o deploy ficou `ready`.
5. Fazer um pedido `GET /api/v1/admin/bootstrap-status`; antes do bootstrap, o resultado esperado é `{"completed":false}`.
6. Só após autorização expressa, executar o bootstrap de `SUPER_ADMIN_PRINCIPAL` com o segredo configurado.
7. Confirmar login, alteração de password, logout, gestão de ADMIN/SUPER_ADMIN e matriz de permissões.
8. Criar empresa/plano/código de activação apenas com dados de teste; validar activação, repetição idempotente, refresh, status e revogação.
9. Depois do bootstrap bem-sucedido, remover `ADMIN_BOOTSTRAP_SECRET` do site de teste e publicar novo deploy para eliminar a variável do runtime.

## Chaves Ed25519

`npm run generate-key` gera e imprime uma JWK privada e uma pública. Executar apenas num terminal privado. Guardar a privada num gestor de segredos/Netlify e a pública no cliente de teste. Não reutilizar a chave de produção. O script não grava ficheiros automaticamente.

## Migration

A branch de teste já apresenta as colunas, constraints e índices da hierarquia administrativa, incluindo `SUPER_ADMIN_PRINCIPAL`, e tem `admin_users` vazio. A migration `001_admin_hierarchy.sql` é histórica e exige exactamente um `SUPER_ADMIN` antigo para promover; **não a executar novamente nesta branch**. Ver `migrations/README.md`.

## Critério de conclusão

O Licensing Server só pode ser declarado concluído depois de testes reais no deploy de teste e na branch Neon de teste. Testes locais não comprovam integração, CORS em produção, configuração de segredos, execução de funções Netlify nem o fluxo completo de activação.

# Estado das migrations

`001_admin_hierarchy.sql` foi criada para promover uma conta `SUPER_ADMIN` existente a `SUPER_ADMIN_PRINCIPAL` e acrescentar campos/índices administrativos.

A inspecção read-only da branch de teste `br-summer-bird-zayl0nyj` confirmou que:

- `admin_users` já contém `display_name`, `email`, `must_change_password`, `temporary_password_expires_at` e `created_by_admin_id`;
- a constraint de `role` já aceita `SUPER_ADMIN_PRINCIPAL`, `SUPER_ADMIN`, `ADMIN`, `SUPPORT` e `AUDITOR`;
- os índices de email, principal único e criador já existem;
- a tabela `admin_users` está vazia.

Por isso, **não executar `001_admin_hierarchy.sql` novamente na branch de teste**. A migration aborta deliberadamente quando não encontra exactamente um `SUPER_ADMIN` antigo. Qualquer migration futura deve ser criada e validada numa branch isolada antes de ser aplicada.

BEGIN;

-- Abort rather than guessing which account owns the principal authority.
DO $$
DECLARE n integer;
BEGIN
  SELECT COUNT(*) INTO n FROM admin_users WHERE role = 'SUPER_ADMIN';
  IF n <> 1 THEN
    RAISE EXCEPTION 'Expected exactly one existing SUPER_ADMIN to promote; found %', n;
  END IF;
END $$;

ALTER TABLE admin_users
  ADD COLUMN IF NOT EXISTS display_name text,
  ADD COLUMN IF NOT EXISTS email text,
  ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS temporary_password_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS created_by_admin_id uuid;

UPDATE admin_users SET display_name = username WHERE display_name IS NULL OR btrim(display_name) = '';
ALTER TABLE admin_users ALTER COLUMN display_name SET NOT NULL;

ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS admin_users_role_check;
ALTER TABLE admin_users ADD CONSTRAINT admin_users_role_check
  CHECK (role = ANY (ARRAY['SUPER_ADMIN_PRINCIPAL','SUPER_ADMIN','ADMIN','SUPPORT','AUDITOR']::text[]));

UPDATE admin_users SET role = 'SUPER_ADMIN_PRINCIPAL', updated_at = now()
WHERE role = 'SUPER_ADMIN';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'admin_users_created_by_admin_id_fkey') THEN
    ALTER TABLE admin_users ADD CONSTRAINT admin_users_created_by_admin_id_fkey
      FOREIGN KEY (created_by_admin_id) REFERENCES admin_users(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS admin_users_email_lower_key
  ON admin_users (lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS admin_users_single_principal_key
  ON admin_users ((role)) WHERE role = 'SUPER_ADMIN_PRINCIPAL';
CREATE INDEX IF NOT EXISTS admin_users_created_by_idx ON admin_users(created_by_admin_id);

COMMIT;

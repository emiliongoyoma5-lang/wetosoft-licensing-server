CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legal_name text NOT NULL,
  email text NOT NULL,
  nif text,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE,
  name text NOT NULL,
  duration_days integer NOT NULL CHECK (duration_days > 0),
  features jsonb NOT NULL DEFAULT '{}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  plan_id uuid NOT NULL REFERENCES plans(id),
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED','EXPIRED')),
  features jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > starts_at)
);
CREATE INDEX IF NOT EXISTS licenses_tenant_idx ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS licenses_status_expiry_idx ON licenses(status, expires_at);

CREATE TABLE IF NOT EXISTS activation_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL UNIQUE,
  license_id uuid NOT NULL REFERENCES licenses(id),
  status text NOT NULL DEFAULT 'UNUSED' CHECK (status IN ('UNUSED','ACTIVATED','REVOKED')),
  activated_at timestamptz,
  installation_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS activation_codes_license_idx ON activation_codes(license_id);

CREATE TABLE IF NOT EXISTS installations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id uuid NOT NULL REFERENCES licenses(id),
  installation_id text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  UNIQUE(license_id, installation_id)
);

CREATE TABLE IF NOT EXISTS license_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  license_id uuid REFERENCES licenses(id),
  tenant_id uuid REFERENCES tenants(id),
  installation_id text,
  event text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS license_events_license_idx ON license_events(license_id, created_at DESC);

INSERT INTO plans(code, name, duration_days, features)
VALUES
  ('QUARTERLY', 'Trimestral', 90, '{"all":true}'::jsonb),
  ('SEMIANNUAL', 'Semestral', 180, '{"all":true}'::jsonb),
  ('ANNUAL', 'Anual', 365, '{"all":true}'::jsonb)
ON CONFLICT (code) DO NOTHING;

import { neon } from '@neondatabase/serverless';
import { SignJWT, importJWK } from 'jose';
import { createHash, timingSafeEqual } from 'node:crypto';
import { randomToken, sha256, hashPassword, verifyPassword } from './auth.mjs';

const json = (statusCode, body, extra = {}) => ({
  statusCode,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    ...extra
  },
  body: JSON.stringify(body)
});

const getDb = () => {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL_MISSING');
  return neon(process.env.DATABASE_URL);
};

const hash = value => createHash('sha256').update(String(value), 'utf8').digest('hex');

function parseBody(event) {
  try {
    return event.body ? JSON.parse(event.body) : {};
  } catch {
    return null;
  }
}

function header(event, name) {
  const headers = event.headers || {};
  const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
  return key ? String(headers[key] || '') : '';
}

function bearer(event) {
  const authorization = header(event, 'authorization').replace(/^Bearer\s+/i, '').trim();
  if (authorization) return authorization;

  const cookie = header(event, 'cookie');
  const match = cookie.match(/(?:^|;\s*)ws_admin_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

function secretMatches(provided, expected) {
  if (!provided || !expected) return false;
  const a = createHash('sha256').update(provided, 'utf8').digest();
  const b = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(a, b);
}

function cookie(token, maxAge = 28800) {
  return `ws_admin_session=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function validInstallationId(value) {
  return typeof value === 'string' &&
    /^[A-Za-z0-9._-]{8,128}$/.test(value.trim());
}

function requireSigningConfig() {
  if (!process.env.LICENSE_PRIVATE_JWK_JSON ||
      !process.env.LICENSE_ISSUER ||
      !process.env.LICENSE_AUDIENCE) {
    const error = new Error('LICENSE_SIGNING_NOT_CONFIGURED');
    error.code = 'LICENSE_SIGNING_NOT_CONFIGURED';
    throw error;
  }
}

async function signLicense(license, tenant, plan, installationId) {
  requireSigningConfig();

  let jwk;
  try {
    jwk = JSON.parse(process.env.LICENSE_PRIVATE_JWK_JSON);
  } catch {
    const error = new Error('LICENSE_PRIVATE_JWK_INVALID');
    error.code = 'LICENSE_PRIVATE_JWK_INVALID';
    throw error;
  }

  const key = await importJWK(jwk, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    typ: 'WetoSoftLicense',
    tenantId: tenant.id,
    company: tenant.legal_name,
    email: tenant.email,
    plan: plan.code,
    licenseId: license.id,
    installationId,
    startsAt: new Date(license.starts_at).toISOString(),
    expiresAt: new Date(license.expires_at).toISOString(),
    features: license.features ?? {}
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'wetosoft-license-1' })
    .setIssuer(process.env.LICENSE_ISSUER)
    .setAudience(process.env.LICENSE_AUDIENCE)
    .setIssuedAt(now)
    .setJti(`${license.id}:${installationId}`)
    .sign(key);
}

async function adminSession(event, roles = []) {
  const token = bearer(event);
  if (!token) return null;

  const db = getDb();
  const rows = await db`
    SELECT u.id, u.username, u.role
    FROM admin_sessions s
    JOIN admin_users u ON u.id = s.admin_user_id
    WHERE s.token_hash = ${sha256(token)}
      AND s.expires_at > now()
      AND u.active = true
    LIMIT 1
  `;

  if (!rows.length) return null;
  if (roles.length && !roles.includes(rows[0].role)) return null;

  await db`
    UPDATE admin_sessions
    SET last_seen_at = now()
    WHERE token_hash = ${sha256(token)}
  `;

  return rows[0];
}

async function bootstrapAdmin(event) {
  const configured = process.env.ADMIN_BOOTSTRAP_SECRET;
  if (!configured) return json(503, { error: 'BOOTSTRAP_NOT_CONFIGURED' });

  if (!secretMatches(header(event, 'x-bootstrap-secret'), configured)) {
    return json(401, { error: 'INVALID_BOOTSTRAP_SECRET' });
  }

  const input = parseBody(event);
  if (!input?.username || !input?.password) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const username = String(input.username).trim();
  const password = String(input.password);

  if (!/^[A-Za-z0-9._-]{3,64}$/.test(username)) {
    return json(400, { error: 'INVALID_USERNAME' });
  }
  if (password.length < 12) {
    return json(400, { error: 'PASSWORD_TOO_SHORT' });
  }

  const db = getDb();
  const passwordHash = await hashPassword(password);
  const sessionToken = randomToken(32);
  const sessionHash = sha256(sessionToken);

  const rows = await db`
    WITH claimed AS (
      UPDATE admin_bootstrap
      SET claimed_at = now()
      WHERE id = 1
        AND claimed_at IS NULL
        AND NOT EXISTS (SELECT 1 FROM admin_users)
      RETURNING id
    ),
    inserted AS (
      INSERT INTO admin_users(username, password_hash, role)
      SELECT ${username}, ${passwordHash}, 'SUPER_ADMIN'
      FROM claimed
      RETURNING id, username, role
    ),
    session_created AS (
      INSERT INTO admin_sessions(admin_user_id, token_hash, expires_at)
      SELECT id, ${sessionHash}, now() + interval '8 hours'
      FROM inserted
      RETURNING admin_user_id
    ),
    event_created AS (
      INSERT INTO license_events(event, metadata)
      SELECT 'ADMIN_BOOTSTRAP',
             ${JSON.stringify({ username })}::jsonb
      FROM inserted
      RETURNING id
    )
    SELECT id, username, role
    FROM inserted
  `;

  if (!rows.length) {
    return json(409, { error: 'BOOTSTRAP_ALREADY_COMPLETED' });
  }

  return json(201, {
    user: {
      id: rows[0].id,
      username: rows[0].username,
      role: rows[0].role
    },
    expiresIn: 28800
  }, { 'set-cookie': cookie(sessionToken) });
}

async function login(event) {
  const input = parseBody(event);
  if (!input?.username || typeof input.password !== 'string') {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const username = String(input.username).trim();
  if (!username) return json(400, { error: 'INVALID_REQUEST' });

  const db = getDb();
  const rows = await db`
    SELECT id, username, password_hash, role
    FROM admin_users
    WHERE username = ${username}
      AND active = true
    LIMIT 1
  `;

  if (!rows.length || !(await verifyPassword(input.password, rows[0].password_hash))) {
    return json(401, { error: 'INVALID_CREDENTIALS' });
  }

  const token = randomToken(32);
  const tokenHash = sha256(token);

  await db`
    WITH session_created AS (
      INSERT INTO admin_sessions(admin_user_id, token_hash, expires_at)
      VALUES (${rows[0].id}, ${tokenHash}, now() + interval '8 hours')
      RETURNING admin_user_id
    )
    INSERT INTO license_events(event, metadata)
    SELECT 'ADMIN_LOGIN',
           ${JSON.stringify({ adminUserId: rows[0].id, username: rows[0].username })}::jsonb
    FROM session_created
  `;

  return json(200, {
    expiresIn: 28800,
    user: {
      id: rows[0].id,
      username: rows[0].username,
      role: rows[0].role
    }
  }, { 'set-cookie': cookie(token) });
}

async function logout(event) {
  const token = bearer(event);
  if (token) {
    const db = getDb();
    await db`
      DELETE FROM admin_sessions
      WHERE token_hash = ${sha256(token)}
    `;
  }

  return json(200, { ok: true }, {
    'set-cookie': cookie('', 0)
  });
}

async function adminMe(event) {
  const admin = await adminSession(event);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  return json(200, {
    user: {
      id: admin.id,
      username: admin.username,
      role: admin.role
    }
  });
}

async function adminBootstrapStatus() {
  const db = getDb();
  const rows = await db`
    SELECT EXISTS(
      SELECT 1 FROM admin_users WHERE active = true
    ) AS completed
  `;

  return json(200, { completed: Boolean(rows[0]?.completed) });
}

/*
 * Activation is deliberately designed as:
 * 1. Read/validate the license data.
 * 2. Sign the token BEFORE consuming the code.
 * 3. Atomically claim the code + installation + event in one SQL statement.
 *
 * If signing fails, nothing is consumed.
 * If the HTTP response is lost after a successful claim, repeating the same
 * activation from the SAME installation returns a fresh valid token.
 * A different installation receives ACTIVATION_CODE_ALREADY_USED.
 */
async function activation(event) {
  const input = parseBody(event);

  if (
    !input ||
    typeof input.activationCode !== 'string' ||
    typeof input.installationId !== 'string'
  ) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const activationCode = input.activationCode.trim().toUpperCase();
  const installationId = input.installationId.trim();

  if (!/^[A-Za-z0-9-]{8,128}$/.test(activationCode)) {
    return json(400, { error: 'INVALID_ACTIVATION_CODE' });
  }

  if (!validInstallationId(installationId)) {
    return json(400, { error: 'INVALID_INSTALLATION_ID' });
  }

  const db = getDb();
  const codeHash = hash(activationCode);

  /*
   * First try an unused code. No mutation happens until the token has
   * successfully been signed.
   */
  const candidates = await db`
    SELECT
      ac.id AS activation_id,
      ac.license_id,
      l.tenant_id,
      l.starts_at,
      l.expires_at,
      l.status AS license_status,
      l.features,
      t.legal_name,
      t.email,
      t.status AS tenant_status,
      p.code AS plan_code
    FROM activation_codes ac
    JOIN licenses l ON l.id = ac.license_id
    JOIN tenants t ON t.id = l.tenant_id
    JOIN plans p ON p.id = l.plan_id
    WHERE ac.code_hash = ${codeHash}
      AND ac.status = 'UNUSED'
    LIMIT 1
  `;

  if (candidates.length) {
    const target = candidates[0];

    if (target.tenant_status === 'CLOSED') {
      return json(403, { error: 'TENANT_CLOSED' });
    }
    if (target.tenant_status !== 'ACTIVE') {
      return json(403, { error: 'TENANT_SUSPENDED' });
    }
    if (target.license_status === 'REVOKED') {
      return json(403, { error: 'LICENSE_REVOKED' });
    }
    if (target.license_status === 'SUSPENDED') {
      return json(403, { error: 'LICENSE_SUSPENDED' });
    }
    if (target.license_status !== 'ACTIVE') {
      return json(403, { error: 'LICENSE_NOT_ACTIVE' });
    }
    if (new Date(target.starts_at).getTime() > Date.now()) {
      return json(403, { error: 'LICENSE_NOT_STARTED' });
    }
    if (new Date(target.expires_at).getTime() <= Date.now()) {
      await db`
        UPDATE licenses
        SET status = 'EXPIRED', updated_at = now()
        WHERE id = ${target.license_id}
          AND status = 'ACTIVE'
      `;
      return json(403, { error: 'LICENSE_EXPIRED' });
    }

    let token;
    try {
      token = await signLicense(
        target,
        { id: target.tenant_id, legal_name: target.legal_name, email: target.email },
        { code: target.plan_code },
        installationId
      );
    } catch (error) {
      if (error.code === 'LICENSE_SIGNING_NOT_CONFIGURED' ||
          error.code === 'LICENSE_PRIVATE_JWK_INVALID') {
        return json(503, { error: 'LICENSE_SIGNING_NOT_CONFIGURED' });
      }
      throw error;
    }

    const claimed = await db`
      WITH claimed AS (
        UPDATE activation_codes
        SET
          status = 'ACTIVATED',
          activated_at = now(),
          installation_id = ${installationId}
        WHERE id = ${target.activation_id}
          AND status = 'UNUSED'
          AND EXISTS (
            SELECT 1
            FROM licenses l
            JOIN tenants t ON t.id = l.tenant_id
            WHERE l.id = ${target.license_id}
              AND l.status = 'ACTIVE'
              AND t.status = 'ACTIVE'
              AND l.starts_at <= now()
              AND l.expires_at > now()
          )
        RETURNING license_id
      ),
      installed AS (
        INSERT INTO installations(license_id, installation_id)
        SELECT license_id, ${installationId}
        FROM claimed
        ON CONFLICT (license_id, installation_id)
        DO UPDATE SET last_seen_at = now(), status = 'ACTIVE'
        RETURNING license_id
      )
      INSERT INTO license_events(
        license_id, tenant_id, installation_id, event, metadata
      )
      SELECT
        ${target.license_id},
        ${target.tenant_id},
        ${installationId},
        'ACTIVATED',
        ${JSON.stringify({ plan: target.plan_code })}::jsonb
      FROM installed
      RETURNING license_id
    `;

    if (!claimed.length) {
      return json(409, { error: 'ACTIVATION_CODE_ALREADY_USED' });
    }

    return json(200, {
      token,
      licenseId: target.license_id,
      tenantId: target.tenant_id,
      expiresAt: new Date(target.expires_at).toISOString()
    });
  }

  /*
   * Idempotent retry:
   * If the previous HTTP response was lost after the DB commit, the same
   * installation can safely retry and receive another signed token.
   */
  const used = await db`
    SELECT
      ac.status AS code_status,
      ac.installation_id,
      l.id,
      l.tenant_id,
      l.starts_at,
      l.expires_at,
      l.status AS license_status,
      l.features,
      t.legal_name,
      t.email,
      t.status AS tenant_status,
      p.code AS plan_code,
      i.status AS installation_status
    FROM activation_codes ac
    JOIN licenses l ON l.id = ac.license_id
    JOIN tenants t ON t.id = l.tenant_id
    JOIN plans p ON p.id = l.plan_id
    LEFT JOIN installations i
      ON i.license_id = l.id
     AND i.installation_id = ac.installation_id
    WHERE ac.code_hash = ${codeHash}
    LIMIT 1
  `;

  if (!used.length) {
    return json(404, { error: 'ACTIVATION_CODE_NOT_FOUND' });
  }

  const existing = used[0];

  if (existing.code_status === 'REVOKED') {
    return json(409, { error: 'ACTIVATION_CODE_REVOKED' });
  }

  if (existing.code_status === 'ACTIVATED' &&
      existing.installation_id === installationId) {
    if (existing.tenant_status === 'CLOSED') {
      return json(403, { error: 'TENANT_CLOSED' });
    }
    if (existing.tenant_status !== 'ACTIVE') {
      return json(403, { error: 'TENANT_SUSPENDED' });
    }
    if (existing.license_status === 'REVOKED') {
      return json(403, { error: 'LICENSE_REVOKED' });
    }
    if (existing.license_status === 'SUSPENDED') {
      return json(403, { error: 'LICENSE_SUSPENDED' });
    }
    if (existing.license_status !== 'ACTIVE') {
      return json(403, { error: 'LICENSE_NOT_ACTIVE' });
    }
    if (new Date(existing.starts_at).getTime() > Date.now()) {
      return json(403, { error: 'LICENSE_NOT_STARTED' });
    }
    if (new Date(existing.expires_at).getTime() <= Date.now()) {
      await db`
        UPDATE licenses
        SET status = 'EXPIRED', updated_at = now()
        WHERE id = ${existing.id}
          AND status = 'ACTIVE'
      `;
      return json(403, { error: 'LICENSE_EXPIRED' });
    }
    if (existing.installation_status !== 'ACTIVE') {
      return json(403, { error: 'INSTALLATION_NOT_ACTIVE' });
    }
    let token;
    try {
      token = await signLicense(
        existing,
        { id: existing.tenant_id, legal_name: existing.legal_name, email: existing.email },
        { code: existing.plan_code },
        installationId
      );
    } catch (error) {
      if (error.code === 'LICENSE_SIGNING_NOT_CONFIGURED' ||
          error.code === 'LICENSE_PRIVATE_JWK_INVALID') {
        return json(503, { error: 'LICENSE_SIGNING_NOT_CONFIGURED' });
      }
      throw error;
    }

    await db`
      UPDATE installations
      SET last_seen_at = now()
      WHERE license_id = ${existing.id}
        AND installation_id = ${installationId}
        AND status = 'ACTIVE'
    `;

    return json(200, {
      token,
      licenseId: existing.id,
      tenantId: existing.tenant_id,
      expiresAt: new Date(existing.expires_at).toISOString(),
      retry: true
    });
  }

  if (existing.code_status === 'ACTIVATED') {
    return json(409, { error: 'ACTIVATION_CODE_ALREADY_USED' });
  }

  return json(403, { error: 'LICENSE_NOT_ACTIVE' });
}

async function refresh(event) {
  const input = parseBody(event);

  if (
    !input?.licenseId ||
    typeof input.installationId !== 'string' ||
    !validInstallationId(input.installationId)
  ) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const installationId = input.installationId.trim();
  const db = getDb();

  const rows = await db`
    SELECT
      l.id,
      l.tenant_id,
      l.starts_at,
      l.expires_at,
      l.status,
      l.features,
      t.legal_name,
      t.email,
      t.status AS tenant_status,
      p.code AS plan_code
    FROM licenses l
    JOIN tenants t ON t.id = l.tenant_id
    JOIN plans p ON p.id = l.plan_id
    JOIN installations i
      ON i.license_id = l.id
     AND i.installation_id = ${installationId}
     AND i.status = 'ACTIVE'
    WHERE l.id = ${input.licenseId}
    LIMIT 1
  `;

  if (!rows.length) {
    return json(404, { error: 'LICENSE_OR_INSTALLATION_NOT_FOUND' });
  }

  const license = rows[0];

  if (license.tenant_status === 'CLOSED') {
    return json(403, { error: 'TENANT_CLOSED' });
  }
  if (license.tenant_status !== 'ACTIVE') {
    return json(403, { error: 'TENANT_SUSPENDED' });
  }
  if (license.status === 'REVOKED') {
    return json(403, { error: 'LICENSE_REVOKED' });
  }
  if (license.status === 'SUSPENDED') {
    return json(403, { error: 'LICENSE_SUSPENDED' });
  }
  if (license.status !== 'ACTIVE') {
    return json(403, { error: 'LICENSE_NOT_ACTIVE' });
  }
  if (new Date(license.starts_at).getTime() > Date.now()) {
    return json(403, { error: 'LICENSE_NOT_STARTED' });
  }

  if (new Date(license.expires_at).getTime() <= Date.now()) {
    await db`
      UPDATE licenses
      SET status = 'EXPIRED', updated_at = now()
      WHERE id = ${license.id}
        AND status = 'ACTIVE'
    `;
    return json(403, { error: 'LICENSE_EXPIRED' });
  }

  let token;
  try {
    token = await signLicense(
      license,
      { id: license.tenant_id, legal_name: license.legal_name, email: license.email },
      { code: license.plan_code },
      installationId
    );
  } catch (error) {
    if (error.code === 'LICENSE_SIGNING_NOT_CONFIGURED' ||
        error.code === 'LICENSE_PRIVATE_JWK_INVALID') {
      return json(503, { error: 'LICENSE_SIGNING_NOT_CONFIGURED' });
    }
    throw error;
  }

  await db`
    WITH touched AS (
      UPDATE installations
      SET last_seen_at = now()
      WHERE license_id = ${license.id}
        AND installation_id = ${installationId}
        AND status = 'ACTIVE'
      RETURNING license_id
    )
    INSERT INTO license_events(
      license_id, tenant_id, installation_id, event
    )
    SELECT ${license.id}, ${license.tenant_id}, ${installationId}, 'REFRESHED'
    FROM touched
  `;

  return json(200, {
    token,
    licenseId: license.id,
    expiresAt: new Date(license.expires_at).toISOString()
  });
}

async function status(event) {
  const input = parseBody(event);

  if (
    !input?.licenseId ||
    typeof input.installationId !== 'string' ||
    !validInstallationId(input.installationId)
  ) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const installationId = input.installationId.trim();
  const db = getDb();

  const rows = await db`
    SELECT
      l.id,
      l.tenant_id,
      l.starts_at,
      l.expires_at,
      l.status,
      t.legal_name,
      t.status AS tenant_status,
      p.code AS plan_code
    FROM licenses l
    JOIN tenants t ON t.id = l.tenant_id
    JOIN plans p ON p.id = l.plan_id
    JOIN installations i
      ON i.license_id = l.id
     AND i.installation_id = ${installationId}
     AND i.status = 'ACTIVE'
    WHERE l.id = ${input.licenseId}
    LIMIT 1
  `;

  if (!rows.length) return json(404, { error: 'NOT_FOUND' });

  const license = rows[0];

  let effectiveStatus = license.status;

  if (license.status === 'REVOKED') {
    effectiveStatus = 'REVOKED';
  } else if (license.status === 'SUSPENDED') {
    effectiveStatus = 'SUSPENDED';
  } else if (license.status === 'EXPIRED') {
    effectiveStatus = 'EXPIRED';
  } else if (license.tenant_status === 'CLOSED') {
    effectiveStatus = 'TENANT_CLOSED';
  } else if (license.tenant_status !== 'ACTIVE') {
    effectiveStatus = 'TENANT_SUSPENDED';
  } else if (new Date(license.starts_at).getTime() > Date.now()) {
    effectiveStatus = 'NOT_STARTED';
  } else if (new Date(license.expires_at).getTime() <= Date.now()) {
    await db`
      UPDATE licenses
      SET status = 'EXPIRED', updated_at = now()
      WHERE id = ${license.id}
        AND status = 'ACTIVE'
    `;
    effectiveStatus = 'EXPIRED';
  }

  if (effectiveStatus === 'ACTIVE') {
    await db`
      UPDATE installations
      SET last_seen_at = now()
      WHERE license_id = ${license.id}
        AND installation_id = ${installationId}
        AND status = 'ACTIVE'
    `;
  }

  return json(200, {
    licenseId: license.id,
    tenantId: license.tenant_id,
    company: license.legal_name,
    plan: license.plan_code,
    status: effectiveStatus,
    startsAt: new Date(license.starts_at).toISOString(),
    expiresAt: new Date(license.expires_at).toISOString(),
    serverTime: new Date().toISOString()
  });
}

async function adminCreateTenant(event) {
  const admin = await adminSession(event, ['SUPER_ADMIN', 'ADMIN']);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  const input = parseBody(event);
  if (!input?.legalName || !input?.email) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const legalName = String(input.legalName).trim();
  const email = String(input.email).trim();
  const nif = input.nif ? String(input.nif).trim() : null;

  if (!legalName || legalName.length > 200 || !email || email.length > 254) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const db = getDb();
  const rows = await db`
    INSERT INTO tenants(legal_name, email, nif)
    VALUES (${legalName}, ${email}, ${nif})
    RETURNING id, legal_name, email, nif, status
  `;

  return json(201, rows[0]);
}

async function adminListTenants(event) {
  const admin = await adminSession(event);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  const db = getDb();
  const rows = await db`
    SELECT id, legal_name, email, nif, status, created_at
    FROM tenants
    ORDER BY created_at DESC
    LIMIT 200
  `;

  return json(200, { items: rows });
}

async function adminCreateCode(event) {
  const admin = await adminSession(event, ['SUPER_ADMIN', 'ADMIN']);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  const input = parseBody(event);
  if (!input?.tenantId || !input?.planCode) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const db = getDb();
  const plans = await db`
    SELECT id, code, duration_days, features
    FROM plans
    WHERE code = ${String(input.planCode).trim().toUpperCase()}
      AND active = true
    LIMIT 1
  `;
  if (!plans.length) return json(404, { error: 'PLAN_NOT_FOUND' });

  const tenants = await db`
    SELECT id, status
    FROM tenants
    WHERE id = ${input.tenantId}
    LIMIT 1
  `;
  if (!tenants.length) return json(404, { error: 'TENANT_NOT_FOUND' });
  if (tenants[0].status !== 'ACTIVE') {
    return json(409, { error: 'TENANT_NOT_ACTIVE' });
  }

  const plan = plans[0];
  const start = input.startsAt ? new Date(input.startsAt) : new Date();

  if (!Number.isFinite(start.getTime())) {
    return json(400, { error: 'INVALID_START_DATE' });
  }

  const expiry = new Date(start.getTime() + Number(plan.duration_days) * 86400000);
  const activationCode = `WS-${randomToken(15).toUpperCase()}`;
  const codeHash = hash(activationCode);

  /*
   * License + activation code + audit event are one database statement.
   * There is no partially-created license.
   */
  const rows = await db`
    WITH new_license AS (
      INSERT INTO licenses(
        tenant_id, plan_id, starts_at, expires_at, features
      )
      VALUES (
        ${input.tenantId},
        ${plan.id},
        ${start.toISOString()},
        ${expiry.toISOString()},
        ${JSON.stringify(plan.features ?? {})}::jsonb
      )
      RETURNING id, tenant_id
    ),
    new_code AS (
      INSERT INTO activation_codes(code_hash, license_id)
      SELECT ${codeHash}, id
      FROM new_license
      RETURNING license_id
    ),
    event_created AS (
      INSERT INTO license_events(
        license_id, tenant_id, event, metadata
      )
      SELECT
        l.id,
        l.tenant_id,
        'CODE_CREATED',
        ${JSON.stringify({
          plan: plan.code,
          adminUserId: admin.id
        })}::jsonb
      FROM new_license l
      JOIN new_code c ON c.license_id = l.id
      RETURNING id
    )
    SELECT id FROM new_license
  `;

  if (!rows.length) {
    return json(500, { error: 'LICENSE_CREATION_FAILED' });
  }

  return json(201, {
    licenseId: rows[0].id,
    activationCode,
    startsAt: start.toISOString(),
    expiresAt: expiry.toISOString()
  });
}

async function adminListLicenses(event) {
  const admin = await adminSession(event);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  const db = getDb();
  const rows = await db`
    SELECT
      l.id,
      l.tenant_id,
      t.legal_name,
      p.code AS plan,
      l.starts_at,
      l.expires_at,
      l.status
    FROM licenses l
    JOIN tenants t ON t.id = l.tenant_id
    JOIN plans p ON p.id = l.plan_id
    ORDER BY l.created_at DESC
    LIMIT 200
  `;

  return json(200, { items: rows });
}

async function adminRevoke(event) {
  const admin = await adminSession(event, ['SUPER_ADMIN', 'ADMIN']);
  if (!admin) return json(401, { error: 'UNAUTHORIZED' });

  const input = parseBody(event);
  if (!input?.licenseId) {
    return json(400, { error: 'INVALID_REQUEST' });
  }

  const db = getDb();

  const rows = await db`
    WITH revoked AS (
      UPDATE licenses
      SET status = 'REVOKED', updated_at = now()
      WHERE id = ${input.licenseId}
      RETURNING id, tenant_id
    ),
    installations_revoked AS (
      UPDATE installations
      SET status = 'REVOKED'
      WHERE license_id IN (SELECT id FROM revoked)
      RETURNING license_id
    ),
    codes_revoked AS (
      UPDATE activation_codes
      SET status = 'REVOKED'
      WHERE license_id IN (SELECT id FROM revoked)
        AND status = 'UNUSED'
      RETURNING license_id
    )
    INSERT INTO license_events(
      license_id, tenant_id, event, metadata
    )
    SELECT
      id,
      tenant_id,
      'REVOKED',
      ${JSON.stringify({ adminUserId: admin.id })}::jsonb
    FROM revoked
    RETURNING license_id
  `;

  if (!rows.length) return json(404, { error: 'LICENSE_NOT_FOUND' });

  return json(200, { ok: true });
}

export const handler = async event => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return {
        statusCode: 204,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type,authorization',
          'access-control-max-age': '86400'
        },
        body: ''
      };
    }

    const path = (event.path || '').replace(/\/+/g, '/');

    if (path.endsWith('/auth/login') && event.httpMethod === 'POST') return login(event);
    if (path.endsWith('/auth/logout') && event.httpMethod === 'POST') return logout(event);
    if (path.endsWith('/admin/me') && event.httpMethod === 'GET') return adminMe(event);
    if (path.endsWith('/admin/bootstrap') && event.httpMethod === 'POST') return bootstrapAdmin(event);
    if (path.endsWith('/admin/bootstrap-status') && event.httpMethod === 'GET') return adminBootstrapStatus();

    if (event.httpMethod !== 'POST' && event.httpMethod !== 'GET') {
      return json(405, { error: 'METHOD_NOT_ALLOWED' });
    }

    if (path.endsWith('/activation')) return activation(event);
    if (path.endsWith('/license/refresh')) return refresh(event);
    if (path.endsWith('/license/status')) return status(event);
    if (path.endsWith('/admin/tenant') && event.httpMethod === 'POST') return adminCreateTenant(event);
    if (path.endsWith('/admin/tenants') && event.httpMethod === 'GET') return adminListTenants(event);
    if (path.endsWith('/admin/activation-code') && event.httpMethod === 'POST') return adminCreateCode(event);
    if (path.endsWith('/admin/licenses') && event.httpMethod === 'GET') return adminListLicenses(event);
    if (path.endsWith('/admin/license/revoke') && event.httpMethod === 'POST') return adminRevoke(event);

    return json(404, { error: 'NOT_FOUND' });
  } catch (error) {
    console.error('licensing-api-error', {
      code: error?.code,
      message: error?.message
    });

    if (
      error?.code === 'LICENSE_SIGNING_NOT_CONFIGURED' ||
      error?.code === 'LICENSE_PRIVATE_JWK_INVALID'
    ) {
      return json(503, { error: 'LICENSE_SIGNING_NOT_CONFIGURED' });
    }

    return json(500, { error: 'INTERNAL_ERROR' });
  }
};

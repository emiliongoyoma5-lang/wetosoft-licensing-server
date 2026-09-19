import { neon } from '@neondatabase/serverless';
import { SignJWT, importJWK } from 'jose';
import { createHash } from 'node:crypto';
import { randomToken, sha256, verifyPassword } from './auth.mjs';

const json = (statusCode, body, extra={}) => ({ statusCode, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra }, body: JSON.stringify(body) });
const getDb = () => { if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL_MISSING'); return neon(process.env.DATABASE_URL); };
const hash = value => createHash('sha256').update(value, 'utf8').digest('hex');

function body(event) { try { return event.body ? JSON.parse(event.body) : {}; } catch { return null; } }
function bearer(event) { const h=event.headers?.authorization?.replace(/^Bearer\s+/i, '').trim(); if(h) return h; const cookie=event.headers?.cookie||event.headers?.Cookie||''; const m=cookie.match(/(?:^|;\s*)ws_admin_session=([^;]+)/); return m ? decodeURIComponent(m[1]) : ''; }

async function adminSession(event, roles=[]) {
  const token = bearer(event); if (!token) return null;
  const db = getDb();
  const rows = await db`
    SELECT u.id, u.username, u.role
    FROM admin_sessions s JOIN admin_users u ON u.id=s.admin_user_id
    WHERE s.token_hash=${sha256(token)} AND s.expires_at > now() AND u.active=true LIMIT 1`;
  if (!rows.length || (roles.length && !roles.includes(rows[0].role))) return null;
  await db`UPDATE admin_sessions SET last_seen_at=now() WHERE token_hash=${sha256(token)}`;
  return rows[0];
}

async function signLicense(license, tenant, plan, installationId) {
  const raw = process.env.LICENSE_PRIVATE_JWK_JSON;
  if (!raw) throw new Error('LICENSE_PRIVATE_KEY_MISSING');
  const key = await importJWK(JSON.parse(raw), 'EdDSA');
  return new SignJWT({ typ:'WetoSoftLicense', tenantId:tenant.id, company:tenant.legal_name, email:tenant.email, plan:plan.code, licenseId:license.id, installationId, startsAt:new Date(license.starts_at).toISOString(), expiresAt:new Date(license.expires_at).toISOString(), features:license.features })
    .setProtectedHeader({alg:'EdDSA',kid:'wetosoft-license-1'}).setIssuer(process.env.LICENSE_ISSUER).setAudience(process.env.LICENSE_AUDIENCE).setIssuedAt().setJti(license.id).sign(key);
}

async function login(event) {
  const input=body(event); if (!input?.username || !input?.password) return json(400,{error:'INVALID_REQUEST'});
  const db=getDb(); const rows=await db`SELECT id,username,password_hash,role FROM admin_users WHERE username=${input.username} AND active=true LIMIT 1`;
  if (!rows.length || !(await verifyPassword(input.password,rows[0].password_hash))) return json(401,{error:'INVALID_CREDENTIALS'});
  const token=randomToken(32); await db`INSERT INTO admin_sessions(admin_user_id,token_hash,expires_at) VALUES(${rows[0].id},${sha256(token)},now()+interval '8 hours')`;
  await db`INSERT INTO license_events(event,metadata) VALUES('ADMIN_LOGIN',${JSON.stringify({adminUserId:rows[0].id,username:rows[0].username})}::jsonb)`;
  return json(200,{expiresIn:28800,user:{id:rows[0].id,username:rows[0].username,role:rows[0].role}},{'set-cookie':`ws_admin_session=${encodeURIComponent(token)}; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict`});
}

async function logout(event) { const token=bearer(event); if(token){const db=getDb(); await db`DELETE FROM admin_sessions WHERE token_hash=${sha256(token)}`;} return json(200,{ok:true},{'set-cookie':'ws_admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'}); }

async function activation(event) {
  const input=body(event); if(!input || typeof input.activationCode!=='string' || typeof input.installationId!=='string') return json(400,{error:'INVALID_REQUEST'});
  if(!/^[A-Za-z0-9._-]{8,128}$/.test(input.installationId)) return json(400,{error:'INVALID_INSTALLATION_ID'});
  const db=getDb(), codeHash=hash(input.activationCode.trim());
  const rows=await db`
    WITH target AS (SELECT ac.id activation_id,ac.license_id,l.tenant_id,l.starts_at,l.expires_at,l.status license_status,l.features,t.legal_name,t.email,t.status tenant_status,p.code plan_code FROM activation_codes ac JOIN licenses l ON l.id=ac.license_id JOIN tenants t ON t.id=l.tenant_id JOIN plans p ON p.id=l.plan_id WHERE ac.code_hash=${codeHash} AND ac.status='UNUSED' LIMIT 1),
    claimed AS (UPDATE activation_codes ac SET status='ACTIVATED',activated_at=now(),installation_id=${input.installationId} FROM target WHERE ac.id=target.activation_id AND target.tenant_status='ACTIVE' AND target.license_status='ACTIVE' AND target.expires_at>now() RETURNING ac.license_id,target.tenant_id,target.plan_code,target.starts_at,target.expires_at,target.features,target.legal_name,target.email),
    installed AS (INSERT INTO installations(license_id,installation_id) SELECT license_id,${input.installationId} FROM claimed ON CONFLICT(license_id,installation_id) DO UPDATE SET last_seen_at=now(),status='ACTIVE'),
    logged AS (INSERT INTO license_events(license_id,tenant_id,installation_id,event) SELECT license_id,tenant_id,${input.installationId},'ACTIVATED' FROM claimed)
    SELECT * FROM claimed LIMIT 1`;
  if(!rows.length){const exists=await db`SELECT status FROM activation_codes WHERE code_hash=${codeHash} LIMIT 1`; if(!exists.length)return json(404,{error:'ACTIVATION_CODE_NOT_FOUND'}); return json(409,{error:exists[0].status==='ACTIVATED'?'ACTIVATION_CODE_ALREADY_USED': 'LICENSE_NOT_ACTIVE'});}
  const r=rows[0],token=await signLicense({id:r.license_id,starts_at:r.starts_at,expires_at:r.expires_at,features:r.features},{id:r.tenant_id,legal_name:r.legal_name,email:r.email},{code:r.plan_code},input.installationId);
  return json(200,{token,licenseId:r.license_id,tenantId:r.tenant_id,expiresAt:new Date(r.expires_at).toISOString()});
}

async function refresh(event) {
  const input=body(event); if(!input?.licenseId || !input?.installationId)return json(400,{error:'INVALID_REQUEST'}); const db=getDb();
  const rows=await db`SELECT l.id,l.tenant_id,l.starts_at,l.expires_at,l.status,l.features,t.legal_name,t.email,t.status tenant_status,p.code plan_code FROM licenses l JOIN tenants t ON t.id=l.tenant_id JOIN plans p ON p.id=l.plan_id JOIN installations i ON i.license_id=l.id AND i.installation_id=${input.installationId} AND i.status='ACTIVE' WHERE l.id=${input.licenseId} LIMIT 1`;
  if(!rows.length)return json(404,{error:'LICENSE_OR_INSTALLATION_NOT_FOUND'}); const r=rows[0];
  if(r.tenant_status!=='ACTIVE' || r.status!=='ACTIVE')return json(403,{error:'LICENSE_NOT_ACTIVE'});
  if(new Date(r.expires_at).getTime()<=Date.now()){await db`UPDATE licenses SET status='EXPIRED',updated_at=now() WHERE id=${r.id} AND status='ACTIVE'`; return json(403,{error:'LICENSE_EXPIRED'});}
  await db`UPDATE installations SET last_seen_at=now() WHERE license_id=${r.id} AND installation_id=${input.installationId}`;
  await db`INSERT INTO license_events(license_id,tenant_id,installation_id,event) VALUES(${r.id},${r.tenant_id},${input.installationId},'REFRESHED')`;
  const token=await signLicense(r,{id:r.tenant_id,legal_name:r.legal_name,email:r.email},{code:r.plan_code},input.installationId); return json(200,{token,licenseId:r.id,expiresAt:new Date(r.expires_at).toISOString()});
}

async function status(event){const input=body(event);if(!input?.licenseId||!input?.installationId)return json(400,{error:'INVALID_REQUEST'});const db=getDb();const rows=await db`SELECT l.id,l.tenant_id,l.starts_at,l.expires_at,l.status,t.legal_name,p.code plan_code FROM licenses l JOIN tenants t ON t.id=l.tenant_id JOIN plans p ON p.id=l.plan_id JOIN installations i ON i.license_id=l.id AND i.installation_id=${input.installationId} AND i.status='ACTIVE' WHERE l.id=${input.licenseId} LIMIT 1`;if(!rows.length)return json(404,{error:'NOT_FOUND'});const r=rows[0];if(r.status==='ACTIVE'&&new Date(r.expires_at).getTime()<=Date.now()){await db`UPDATE licenses SET status='EXPIRED',updated_at=now() WHERE id=${r.id} AND status='ACTIVE'`;r.status='EXPIRED';}await db`UPDATE installations SET last_seen_at=now() WHERE license_id=${r.id} AND installation_id=${input.installationId}`;return json(200,{licenseId:r.id,tenantId:r.tenant_id,company:r.legal_name,plan:r.plan_code,status:r.status,startsAt:new Date(r.starts_at).toISOString(),expiresAt:new Date(r.expires_at).toISOString(),serverTime:new Date().toISOString()});}

async function adminCreateTenant(event){const a=await adminSession(event,['SUPER_ADMIN','ADMIN']);if(!a)return json(401,{error:'UNAUTHORIZED'});const i=body(event);if(!i?.legalName||!i?.email)return json(400,{error:'INVALID_REQUEST'});const db=getDb();const r=await db`INSERT INTO tenants(legal_name,email,nif) VALUES(${i.legalName},${i.email},${i.nif||null}) RETURNING id,legal_name,email,nif,status`;return json(201,r[0]);}
async function adminListTenants(event){const a=await adminSession(event);if(!a)return json(401,{error:'UNAUTHORIZED'});const db=getDb();return json(200,{items:await db`SELECT id,legal_name,email,nif,status,created_at FROM tenants ORDER BY created_at DESC LIMIT 200`});}
async function adminCreateCode(event){const a=await adminSession(event,['SUPER_ADMIN','ADMIN']);if(!a)return json(401,{error:'UNAUTHORIZED'});const i=body(event);if(!i?.tenantId||!i?.planCode)return json(400,{error:'INVALID_REQUEST'});const db=getDb();const p=await db`SELECT id,code,duration_days,features FROM plans WHERE code=${i.planCode} AND active=true LIMIT 1`;if(!p.length)return json(404,{error:'PLAN_NOT_FOUND'});const t=await db`SELECT id,status FROM tenants WHERE id=${i.tenantId} LIMIT 1`;if(!t.length)return json(404,{error:'TENANT_NOT_FOUND'});if(t[0].status!=='ACTIVE')return json(409,{error:'TENANT_NOT_ACTIVE'});const code=`WS-${randomToken(15).toUpperCase()}`,start=i.startsAt?new Date(i.startsAt):new Date(),expiry=new Date(start.getTime()+p[0].duration_days*86400000);if(!Number.isFinite(start.getTime()))return json(400,{error:'INVALID_START_DATE'});const l=await db`INSERT INTO licenses(tenant_id,plan_id,starts_at,expires_at,features) VALUES(${i.tenantId},${p[0].id},${start.toISOString()},${expiry.toISOString()},${JSON.stringify(p[0].features)}::jsonb) RETURNING id`;await db`INSERT INTO activation_codes(code_hash,license_id) VALUES(${hash(code)},${l[0].id})`;await db`INSERT INTO license_events(license_id,tenant_id,event,metadata) VALUES(${l[0].id},${i.tenantId},'CODE_CREATED',${JSON.stringify({plan:i.planCode,adminUserId:a.id})}::jsonb)`;return json(201,{licenseId:l[0].id,activationCode:code,startsAt:start.toISOString(),expiresAt:expiry.toISOString()});}
async function adminListLicenses(event){const a=await adminSession(event);if(!a)return json(401,{error:'UNAUTHORIZED'});const db=getDb();return json(200,{items:await db`SELECT l.id,l.tenant_id,t.legal_name,p.code plan,l.starts_at,l.expires_at,l.status FROM licenses l JOIN tenants t ON t.id=l.tenant_id JOIN plans p ON p.id=l.plan_id ORDER BY l.created_at DESC LIMIT 200`});}
async function adminRevoke(event){const a=await adminSession(event,['SUPER_ADMIN','ADMIN']);if(!a)return json(401,{error:'UNAUTHORIZED'});const i=body(event);if(!i?.licenseId)return json(400,{error:'INVALID_REQUEST'});const db=getDb();const r=await db`UPDATE licenses SET status='REVOKED',updated_at=now() WHERE id=${i.licenseId} RETURNING id,tenant_id`;if(!r.length)return json(404,{error:'LICENSE_NOT_FOUND'});await db`UPDATE installations SET status='REVOKED' WHERE license_id=${i.licenseId}`;await db`UPDATE activation_codes SET status='REVOKED' WHERE license_id=${i.licenseId} AND status='UNUSED'`;await db`INSERT INTO license_events(license_id,tenant_id,event,metadata) VALUES(${r[0].id},${r[0].tenant_id},'REVOKED',${JSON.stringify({adminUserId:a.id})}::jsonb)`;return json(200,{ok:true});}

export const handler=async event=>{try{if(event.httpMethod==='OPTIONS')return{statusCode:204,headers:{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,OPTIONS','access-control-allow-headers':'content-type,authorization'},body:''};const path=(event.path||'').replace(/\/+/g,'/');if(path.endsWith('/auth/login')&&event.httpMethod==='POST')return login(event);if(path.endsWith('/auth/logout')&&event.httpMethod==='POST')return logout(event);if(event.httpMethod!=='POST'&&event.httpMethod!=='GET')return json(405,{error:'METHOD_NOT_ALLOWED'});if(path.endsWith('/activation'))return activation(event);if(path.endsWith('/license/refresh'))return refresh(event);if(path.endsWith('/license/status'))return status(event);if(path.endsWith('/admin/tenant')&&event.httpMethod==='POST')return adminCreateTenant(event);if(path.endsWith('/admin/tenants')&&event.httpMethod==='GET')return adminListTenants(event);if(path.endsWith('/admin/activation-code'))return adminCreateCode(event);if(path.endsWith('/admin/licenses')&&event.httpMethod==='GET')return adminListLicenses(event);if(path.endsWith('/admin/license/revoke'))return adminRevoke(event);return json(404,{error:'NOT_FOUND'});}catch(error){console.error('licensing-api-error',error);return json(500,{error:'INTERNAL_ERROR'});}};

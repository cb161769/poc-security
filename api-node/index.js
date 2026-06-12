const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK, importSPKI, exportJWK } = require('jose');
const fs = require('fs');
const Redis = require('ioredis');
const CircuitBreaker = require('opossum');

const app = express();
app.use(express.json());
app.disable('x-powered-by');
app.set('etag', false);

/* ================================
   CONFIG — dos reinos
================================ */
const ODOO_URL = process.env.ODOO_URL || 'http://odoo-server:8069';
const KEYCLOAK_BASE = process.env.KEYCLOAK_BASE || 'http://keycloak:8080';

const REALMS = {
  web: {
    issuer:    process.env.WEB_REALM_ISSUER  || 'http://localhost:8080/realms/web-realm',
    jwksUri:   process.env.WEB_REALM_JWKS   || `${KEYCLOAK_BASE}/realms/web-realm/protocol/openid-connect/certs`,
    audience:  'web-api',
    realmName: 'web-realm',
    clientId:  'web-app-client',
  },
  mobile: {
    issuer:    process.env.MOBILE_REALM_ISSUER  || 'http://localhost:8080/realms/mobile-realm',
    jwksUri:   process.env.MOBILE_REALM_JWKS   || `${KEYCLOAK_BASE}/realms/mobile-realm/protocol/openid-connect/certs`,
    audience:  'mobile-api',
    realmName: 'mobile-realm',
    clientId:  'mobile-app-client',
  },
};

/* ================================
   JWKS CLIENTS — uno por reino
================================ */
const jwksOpts = {
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
};

const jwksClients = {
  web:    jwksClient({ jwksUri: REALMS.web.jwksUri,    ...jwksOpts }),
  mobile: jwksClient({ jwksUri: REALMS.mobile.jwksUri, ...jwksOpts }),
};

/* ================================
   REDIS — blacklist · pubkey binding · emergency lockdown
================================ */
const redis = new Redis(process.env.REDIS_URL || 'redis://redis-cache:6379', {
  lazyConnect: true,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  connectTimeout: 2000,
});
redis.on('error', (e) => console.error('[redis] error:', e.message));

async function isTokenBlacklisted(jti, iat) {
  try {
    if (jti) {
      const blocked = await redis.get(`blacklist:jti:${jti}`);
      if (blocked) return true;
    }
    // Emergency lockdown: any token issued before lockdownAt is invalid
    const lockdownAt = await redis.get('emergency:lockdown');
    if (lockdownAt && iat < parseInt(lockdownAt)) return true;
    return false;
  } catch {
    // Redis unavailable — fail open (log and continue); for fail-closed swap to: return true
    console.warn('[blacklist] Redis unavailable — skipping blacklist check');
    return false;
  }
}

async function blacklistJTI(jti, exp) {
  try {
    const ttl = exp - Math.floor(Date.now() / 1000);
    if (jti && ttl > 0) await redis.setex(`blacklist:jti:${jti}`, ttl, '1');
  } catch (e) {
    console.error('[blacklist] Failed to write JTI:', e.message);
  }
}

/* ================================
   PUBKEY BINDING STORE — Redis (distributed)
================================ */
async function getPubKeyBinding(sub) {
  try {
    const data = await redis.get(`pubkey:${sub}`);
    return data ? JSON.parse(data) : null;
  } catch { return null; }
}

async function setPubKeyBinding(sub, key, exp) {
  try {
    const ttl = exp - Math.floor(Date.now() / 1000);
    if (ttl > 0) await redis.setex(`pubkey:${sub}`, ttl, JSON.stringify({ key, exp }));
  } catch {}
}

async function validatePubKeyBinding(req, res, next) {
  const pubKeyB64 = req.headers['x-client-public-key'];
  if (!pubKeyB64) return next();
  const sub = req.jwt.sub;
  const entry = await getPubKeyBinding(sub);
  const now = Math.floor(Date.now() / 1000);
  if (!entry || now > entry.exp || entry.exp !== req.jwt.exp) {
    await setPubKeyBinding(sub, pubKeyB64, req.jwt.exp);
    return next();
  }
  if (entry.key !== pubKeyB64)
    return res.status(403).json({ error: 'Clave de cliente no coincide con la registrada' });
  next();
}

/* ================================
   DETECT CHANNEL — peek sin verificar
================================ */
function detectChannel(token) {
  try {
    const raw = Buffer.from(token.split('.')[1], 'base64url').toString('utf8');
    const { iss } = JSON.parse(raw);
    if (iss === REALMS.web.issuer)    return 'web';
    if (iss === REALMS.mobile.issuer) return 'mobile';
    return null;
  } catch {
    return null;
  }
}

/* ================================
   MIDDLEWARE: VALIDAR JWT (multi-realm)
================================ */
async function validateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token JWT requerido' });
  }

  const token = authHeader.replace('Bearer ', '');
  const channel = req.headers['x-channel'] || detectChannel(token);

  if (!channel || !REALMS[channel]) {
    return res.status(401).json({ error: 'Canal o emisor JWT no reconocido' });
  }

  const realm = REALMS[channel];

  function getKey(header, callback) {
    jwksClients[channel].getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      callback(null, key.getPublicKey());
    });
  }

  jwt.verify(
    token,
    getKey,
    { issuer: realm.issuer, audience: realm.audience, algorithms: ['RS256'], clockTolerance: 30 },
    (err, decoded) => {
      if (err) {
        console.error(`[${channel}] JWT inválido:`, err.message);
        return res.status(401).json({ error: 'JWT inválido' });
      }

      isTokenBlacklisted(decoded.jti, decoded.iat).then(blocked => {
        if (blocked) return res.status(401).json({ error: 'Token revocado' });

        // app_version claim es server-controlled (Keycloak hardcoded mapper) — no falsificable
        const MIN_VERSION = process.env.MIN_APP_VERSION || '1.0.0';
        const tokenVersion = decoded.app_version;
        if (tokenVersion && tokenVersion < MIN_VERSION)
          return res.status(426).json({ error: 'Versión de aplicación no soportada', min_version: MIN_VERSION });

        req.channel = channel;
        req.jwt = {
          sub:         decoded.sub,
          username:    decoded.preferred_username,
          email:       decoded.email,
          roles:       decoded.realm_access?.roles || [],
          client_id:   decoded.azp,
          exp:         decoded.exp,
          jti:         decoded.jti,
          iat:         decoded.iat,
          app_version: decoded.app_version,
        };
        next();
      });
    }
  );
}

/* ================================
   CIRCUIT BREAKER — Odoo AuthZ
   OPEN after 3 failures in 10s window → fast-fail 503 for 30s
================================ */
async function callOdoo(payload) {
  const response = await axios.post(
    `${ODOO_URL}/api/validate-jwt-client`,
    payload,
    {
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || '' },
      timeout: 3000,
    }
  );
  return response.data;
}

const odooBreaker = new CircuitBreaker(callOdoo, {
  timeout: 3000,
  errorThresholdPercentage: 50,
  resetTimeout: 30000,
  volumeThreshold: 3,
  name: 'odoo-authz',
});
odooBreaker.on('open',     () => console.warn('[circuit:odoo] OPEN — failing fast'));
odooBreaker.on('halfOpen', () => console.info('[circuit:odoo] HALF-OPEN — testing'));
odooBreaker.on('close',    () => console.info('[circuit:odoo] CLOSED — recovered'));

async function validateClientInOdoo(req, res, next) {
  try {
    const result = await odooBreaker.fire({
      sub: req.jwt.sub, email: req.jwt.email, client_id: req.jwt.client_id, roles: req.jwt.roles,
    });
    if (!result || result.authorized !== true)
      return res.status(403).json({ error: 'Cliente no autorizado por Odoo' });
    req.client = result.client;
    next();
  } catch (error) {
    if (odooBreaker.opened) {
      console.error('[circuit:odoo] Circuit OPEN:', error.message);
      return res.status(503).set('Retry-After', '30').json({ error: 'Servicio de autorización no disponible temporalmente' });
    }
    console.error('Error Odoo:', error.message);
    return res.status(502).json({ error: 'Error validando cliente en Odoo' });
  }
}

/* ================================
   HELPER: CIFRAR CON JWE
   Web:    clave efímera no-extractable en cliente → forward secrecy por sesión
   Mobile: clave persistida en secure storage del dispositivo
================================ */
async function encryptJWE(payload, clientPubKeyB64, channel) {
  const jwk = JSON.parse(Buffer.from(clientPubKeyB64, 'base64').toString('utf8'));
  const publicKey = await importJWK(jwk, 'RSA-OAEP-256');

  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', svc: 'data', channel })
    .encrypt(publicKey);
}

/* ================================
   ENDPOINT PROTEGIDO
================================ */
app.post('/api/v1/data/register-key', validateJWT, (req, res) => {
  const pubKeyB64 = req.headers['x-client-public-key'];
  if (!pubKeyB64) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });
  const sub = req.jwt.sub;
  const existing = pubKeyStore.get(sub);
  const now = Math.floor(Date.now() / 1000);
  if (existing && now <= existing.exp && existing.key !== pubKeyB64)
    return res.status(409).json({ error: 'Ya existe una clave registrada para este sub' });
  pubKeyStore.set(sub, { key: pubKeyB64, exp: req.jwt.exp });
  res.json({ registered: true, sub: req.jwt.sub });
});

app.get('/api/v1/data', validateJWT, validateClientInOdoo, validatePubKeyBinding, async (req, res) => {
  const clientPubKeyB64 = req.headers['x-client-public-key'];

  if (!clientPubKeyB64) {
    return res.status(400).json({ error: 'X-Client-Public-Key requerido' });
  }

  const payload = {
    message:   'Datos protegidos recuperados con éxito',
    channel:   req.channel,
    timestamp: new Date().toISOString(),
    user:   { sub: req.jwt.sub, email: req.jwt.email, roles: req.jwt.roles },
    client: req.client,
  };

  try {
    const jwe = await encryptJWE(payload, clientPubKeyB64, req.channel);
    res.set('Content-Type', 'application/jose').set('Cache-Control', 'no-store').send(jwe);
  } catch (err) {
    console.error('JWE encrypt error:', err.message);
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

/* ================================
   ENDPOINT INTERNO
================================ */
app.post('/internal/validate-user', validateJWT, async (req, res) => {
  const { username, password } = req.body;
  try {
    const response = await axios.post(`${ODOO_URL}/jsonrpc`, {
      jsonrpc: '2.0', method: 'call',
      params: { model: 'x_api_usuarios', method: 'validate_external_credentials', args: [username, password] },
    });
    if (response.data.result?.status === 'success') {
      res.json(response.data.result);
    } else {
      res.status(401).json({ status: 'error', message: 'Credenciales inválidas en Odoo' });
    }
  } catch {
    res.status(500).json({ status: 'error', message: 'Error de conexión con Odoo' });
  }
});

/* ================================
   CHANGE PASSWORD
   1. Re-autentica con contraseña actual → verifica que es correcta
   2. Obtiene admin token del master realm (cached, renovado 30s antes de exp)
   3. Admin API: PUT /admin/realms/{realm}/users/{sub}/reset-password
================================ */
const KEYCLOAK_ADMIN_USER = process.env.KEYCLOAK_ADMIN_USER || 'admin';
const KEYCLOAK_ADMIN_PASS = process.env.KEYCLOAK_ADMIN_PASS || 'admin';
let _adminToken = null;
let _adminTokenExpiry = 0;

async function fetchAdminToken() {
  if (_adminToken && Date.now() / 1000 < _adminTokenExpiry - 30) return _adminToken;
  const resp = await axios.post(
    `${KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token`,
    new URLSearchParams({
      client_id:  'admin-cli',
      grant_type: 'password',
      username:   KEYCLOAK_ADMIN_USER,
      password:   KEYCLOAK_ADMIN_PASS,
    }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
  );
  _adminToken = resp.data.access_token;
  _adminTokenExpiry = Math.floor(Date.now() / 1000) + resp.data.expires_in;
  return _adminToken;
}

const keycloakAdminBreaker = new CircuitBreaker(fetchAdminToken, {
  timeout: 5000,
  errorThresholdPercentage: 50,
  resetTimeout: 60000,
  volumeThreshold: 2,
  name: 'keycloak-admin',
});
keycloakAdminBreaker.on('open', () => console.warn('[circuit:keycloak-admin] OPEN'));
keycloakAdminBreaker.on('close', () => console.info('[circuit:keycloak-admin] CLOSED'));

async function getAdminToken() {
  return keycloakAdminBreaker.fire();
}

app.post('/change-password', validateJWT, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'currentPassword y newPassword son requeridos' });
  if (newPassword.length < 8)
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });
  if (currentPassword === newPassword)
    return res.status(400).json({ error: 'La nueva contraseña debe ser diferente a la actual' });

  const realm = REALMS[req.channel];
  const tokenUrl = `${KEYCLOAK_BASE}/realms/${realm.realmName}/protocol/openid-connect/token`;

  // Paso 1: re-autenticar con la contraseña actual para verificarla
  try {
    await axios.post(
      tokenUrl,
      new URLSearchParams({
        client_id:  realm.clientId,
        grant_type: 'password',
        username:   req.jwt.username,
        password:   currentPassword,
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
  } catch (err) {
    if (err.response?.status === 401)
      return res.status(400).json({ error: 'Contraseña actual incorrecta' });
    console.error('[change-password] re-auth error:', err.response?.data || err.message);
    return res.status(502).json({ error: 'Error verificando credenciales' });
  }

  // Paso 2: obtener admin token del master realm (módulo-level cache)
  let adminToken;
  try {
    adminToken = await getAdminToken();
  } catch (err) {
    console.error('[change-password] admin token error:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Error interno al actualizar contraseña' });
  }

  // Paso 3: admin API reset-password — el sub del JWT es el userId de Keycloak
  try {
    await axios.put(
      `${KEYCLOAK_BASE}/admin/realms/${realm.realmName}/users/${req.jwt.sub}/reset-password`,
      { type: 'password', value: newPassword, temporary: false },
      { headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' } }
    );
    // Blacklist the current token — password changed, old sessions should not persist
    await blacklistJTI(req.jwt.jti, req.jwt.exp);
    res.json({ success: true });
  } catch (err) {
    console.error('[change-password] reset-password error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Error actualizando contraseña' });
  }
});

/* ================================
   EMERGENCY LOCKDOWN
   POST /admin/lockdown — invalida TODOS los tokens emitidos antes de ahora (iat check)
   Requiere rol admin-api. En producción: restringir a IP interna + admin MFA.
================================ */
app.post('/admin/lockdown', validateJWT, async (req, res) => {
  const roles = req.jwt.roles || [];
  if (!roles.includes('admin-api') && !roles.includes('admin-web'))
    return res.status(403).json({ error: 'Se requiere rol admin' });

  const now = Math.floor(Date.now() / 1000);
  try {
    await redis.set('emergency:lockdown', now);
    console.warn(`[LOCKDOWN] Triggered by ${req.jwt.sub} at ${new Date().toISOString()} — all tokens issued before epoch ${now} are revoked`);
    res.json({ locked: true, revokedBefore: new Date(now * 1000).toISOString() });
  } catch (err) {
    console.error('[lockdown] Redis error:', err.message);
    res.status(500).json({ error: 'No se pudo activar el lockdown' });
  }
});

app.delete('/admin/lockdown', validateJWT, async (req, res) => {
  const roles = req.jwt.roles || [];
  if (!roles.includes('admin-api') && !roles.includes('admin-web'))
    return res.status(403).json({ error: 'Se requiere rol admin' });

  try {
    await redis.del('emergency:lockdown');
    console.info(`[LOCKDOWN] Lifted by ${req.jwt.sub} at ${new Date().toISOString()}`);
    res.json({ locked: false });
  } catch (err) {
    res.status(500).json({ error: 'Error al desactivar lockdown' });
  }
});

/* ================================
   PUBKEY ENDPOINT (público)
================================ */
app.get('/api/v1/pubkey', async (req, res) => {
  try {
    const pem = fs.readFileSync('/shared-keys/pub.pem', 'utf8');
    const key = await importSPKI(pem, 'RSA-OAEP-256');
    const jwk = await exportJWK(key);
    res.json({ alg: 'RSA-OAEP-256', use: 'enc', ...jwk });
  } catch (err) {
    console.error('[api-node] Error leyendo pub.pem:', err.message);
    res.status(503).json({ error: 'Clave pública no disponible' });
  }
});

/* ================================
   START
================================ */
app.listen(3000, () => {
  console.log('🚀 Backend API seguro escuchando en puerto 3000');
  console.log(`   web-realm   → ${REALMS.web.issuer}`);
  console.log(`   mobile-realm→ ${REALMS.mobile.issuer}`);
});

const express = require('express');
const axios   = require('axios');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK, compactDecrypt, importPKCS8 } = require('jose');
const fs = require('fs');
const Redis = require('ioredis');
const CircuitBreaker = require('opossum');

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/jose' }));
app.disable('x-powered-by');
app.set('etag', false);

/* ── CONFIG ─────────────────────────────────────────── */
const ODOO_URL = process.env.ODOO_URL || 'http://odoo-server:8069';

const REALMS = {
  web: {
    issuer:   process.env.WEB_REALM_ISSUER  || 'http://localhost:8080/realms/web-realm',
    jwksUri:  process.env.WEB_REALM_JWKS    || 'http://keycloak:8080/realms/web-realm/protocol/openid-connect/certs',
    audience: 'web-api',
  },
  mobile: {
    issuer:   process.env.MOBILE_REALM_ISSUER || 'http://localhost:8080/realms/mobile-realm',
    jwksUri:  process.env.MOBILE_REALM_JWKS   || 'http://keycloak:8080/realms/mobile-realm/protocol/openid-connect/certs',
    audience: 'mobile-api',
  },
};

const JWKS_OPTS = { cache: true, cacheMaxAge: 10 * 60 * 1000, rateLimit: true, jwksRequestsPerMinute: 10 };

const jwksClients = {
  web:    jwksClient({ jwksUri: REALMS.web.jwksUri,    ...JWKS_OPTS }),
  mobile: jwksClient({ jwksUri: REALMS.mobile.jwksUri, ...JWKS_OPTS }),
};

/* ── REDIS ───────────────────────────────────────────── */
const redis = new Redis(process.env.REDIS_URL || 'redis://redis-cache:6379', {
  lazyConnect: true, enableOfflineQueue: false, maxRetriesPerRequest: 1, connectTimeout: 2000,
});
redis.on('error', (e) => console.error('[redis] error:', e.message));

async function isTokenBlacklisted(jti, iat) {
  try {
    if (jti && await redis.get(`blacklist:jti:${jti}`)) return true;
    const lockdownAt = await redis.get('emergency:lockdown');
    if (lockdownAt && iat < parseInt(lockdownAt)) return true;
    return false;
  } catch {
    console.warn('[blacklist] Redis unavailable — skipping check');
    return false;
  }
}

/* ── PUBKEY BINDING STORE (Redis) ────────────────────── */
async function getPubKeyBinding(sub) {
  try { const d = await redis.get(`pubkey:${sub}`); return d ? JSON.parse(d) : null; } catch { return null; }
}
async function setPubKeyBinding(sub, key, exp) {
  try { const ttl = exp - Math.floor(Date.now() / 1000); if (ttl > 0) await redis.setex(`pubkey:${sub}`, ttl, JSON.stringify({ key, exp })); } catch {}
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

/* ── IDEMPOTENCY STORE (Redis) ───────────────────────── */
const IDEMPOTENCY_TTL_S = 5 * 60;

async function checkIdempotency(req, res, next) {
  const key = req.headers['x-idempotency-key'];
  if (!key) return res.status(400).json({ error: 'X-Idempotency-Key requerido' });
  try {
    const cached = await redis.get(`idempotency:${key}`);
    if (cached) {
      const entry = JSON.parse(cached);
      return res.status(entry.statusCode)
        .set('Content-Type', entry.contentType)
        .set('X-Idempotency-Replayed', 'true')
        .send(entry.body);
    }
  } catch {}
  const originalSend = res.send.bind(res);
  res.send = function(body) {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      redis.setex(`idempotency:${key}`, IDEMPOTENCY_TTL_S, JSON.stringify({
        statusCode: res.statusCode,
        contentType: res.getHeader('Content-Type') || 'application/json',
        body,
      })).catch(() => {});
    }
    return originalSend(body);
  };
  next();
}

/* ── SERVER PRIVATE KEY (para descifrar requests) ───── */
let _privKey = null, _privKeyAt = 0;
async function getServerPrivKey() {
  if (_privKey && Date.now() - _privKeyAt < 3_600_000) return _privKey;
  const pem = fs.readFileSync('/shared-keys/priv.pem', 'utf8');
  _privKey = await importPKCS8(pem, 'RSA-OAEP-256');
  _privKeyAt = Date.now();
  return _privKey;
}

async function decryptRequestBody(req, res, next) {
  const ct = req.headers['content-type'] || '';
  const isMobile = req.channel === 'mobile';

  if (isMobile && !ct.includes('application/jose'))
    return res.status(415).json({ error: 'Canal mobile requiere body cifrado (application/jose)' });

  if (!ct.includes('application/jose')) return next();

  try {
    const key = await getServerPrivKey();
    const { plaintext } = await compactDecrypt(req.body, key);
    req.body = JSON.parse(new TextDecoder().decode(plaintext));
    next();
  } catch {
    _privKey = null;
    return res.status(422).json({ error: 'KEY_ROTATED', message: 'Refetch /api/v1/pubkey y reintenta' });
  }
}

/* ── DETECT CHANNEL ─────────────────────────────────── */
function detectChannel(token) {
  try {
    const { iss } = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    if (iss === REALMS.web.issuer)    return 'web';
    if (iss === REALMS.mobile.issuer) return 'mobile';
    return null;
  } catch { return null; }
}

/* ── MIDDLEWARE: JWT ─────────────────────────────────── */
function validateJWT(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token requerido' });

  const token   = auth.slice(7);
  const channel = req.headers['x-channel'] || detectChannel(token);
  if (!channel) return res.status(401).json({ error: 'Emisor no reconocido' });

  const realm = REALMS[channel];

  function getKey(header, cb) {
    jwksClients[channel].getSigningKey(header.kid, (err, key) => {
      if (err) return cb(err);
      cb(null, key.getPublicKey());
    });
  }

  jwt.verify(token, getKey,
    { issuer: realm.issuer, audience: realm.audience, algorithms: ['RS256'], clockTolerance: 30 },
    (err, decoded) => {
      if (err) {
        console.error(`[payments][${channel}] JWT inválido:`, err.message);
        return res.status(401).json({ error: 'JWT inválido' });
      }

      const roles = decoded.realm_access?.roles || [];
      const allowed = ['user-api', 'admin-api', 'user-web', 'admin-web'];
      if (!roles.some(r => allowed.includes(r)))
        return res.status(403).json({ error: 'Rol insuficiente para el servicio de pagos' });

      isTokenBlacklisted(decoded.jti, decoded.iat).then(blocked => {
        if (blocked) return res.status(401).json({ error: 'Token revocado' });
        const MIN_VERSION = process.env.MIN_APP_VERSION || '1.0.0';
        const tokenVersion = decoded.app_version;
        if (tokenVersion && tokenVersion < MIN_VERSION)
          return res.status(426).json({ error: 'Versión de aplicación no soportada', min_version: MIN_VERSION });
        req.channel = channel;
        req.jwt = { sub: decoded.sub, email: decoded.email, roles, client_id: decoded.azp, exp: decoded.exp, jti: decoded.jti, iat: decoded.iat, app_version: decoded.app_version };
        next();
      });
    }
  );
}

/* ── ODOO AUTHZ + CIRCUIT BREAKER ────────────────────── */
async function callOdoo(payload) {
  const r = await axios.post(`${ODOO_URL}/api/validate-jwt-client`, payload, {
    headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || '' },
    timeout: 3000,
  });
  return r.data;
}
const odooBreaker = new CircuitBreaker(callOdoo, {
  timeout: 3000, errorThresholdPercentage: 50, resetTimeout: 30000, volumeThreshold: 3, name: 'odoo-payments',
});
odooBreaker.on('open',  () => console.warn('[circuit:odoo-payments] OPEN'));
odooBreaker.on('close', () => console.info('[circuit:odoo-payments] CLOSED'));

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
    if (odooBreaker.opened)
      return res.status(503).set('Retry-After', '30').json({ error: 'Servicio de autorización no disponible temporalmente' });
    console.error('[payments] Error Odoo:', error.message);
    return res.status(502).json({ error: 'Error validando cliente en Odoo' });
  }
}

/* ── HELPER: JWE ─────────────────────────────────────── */
async function replyJWE(res, payload, pubKeyB64, channel) {
  const jwk = JSON.parse(Buffer.from(pubKeyB64, 'base64').toString());
  const pub  = await importJWK(jwk, 'RSA-OAEP-256');
  const jwe  = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', svc: 'payments', channel })
    .encrypt(pub);
  res.set('Content-Type', 'application/jose').set('Cache-Control', 'no-store').send(jwe);
}

/* ── ENDPOINTS ───────────────────────────────────────── */

// GET / — listar pagos
app.get('/', validateJWT, validateClientInOdoo, validatePubKeyBinding, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const payload = {
    service: 'payments',
    channel: req.channel,
    user: req.jwt,
    data: [
      { id: 'PAY-001', amount: 199.99, currency: 'USD', method: 'card', status: 'settled',  merchant: 'Acme Corp',    last4: '4242' },
      { id: 'PAY-002', amount: 49.00,  currency: 'USD', method: 'ach',  status: 'pending',  merchant: 'Utility Co',   last4: null   },
      { id: 'PAY-003', amount: 350.00, currency: 'USD', method: 'card', status: 'settled',  merchant: 'Office Supply', last4: '1234' },
    ],
    timestamp: new Date().toISOString(),
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    console.error('[payments] JWE error:', err.message);
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

// POST / — crear pago
app.post('/', validateJWT, validateClientInOdoo, validatePubKeyBinding, decryptRequestBody, checkIdempotency, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const { amount, currency = 'USD', method, merchant } = req.body;
  if (!amount || !method)
    return res.status(422).json({ error: 'amount y method son requeridos' });

  const MAX_AMOUNT = parseFloat(process.env.MAX_PAYMENT_AMOUNT || '5000');
  if (parseFloat(amount) <= 0 || parseFloat(amount) > MAX_AMOUNT)
    return res.status(422).json({ error: `Monto fuera del rango permitido (0–${MAX_AMOUNT})` });

  const validMethods = ['card', 'ach', 'wire'];
  if (!validMethods.includes(method))
    return res.status(422).json({ error: `Método inválido. Permitidos: ${validMethods.join(', ')}` });

  const payload = {
    service: 'payments',
    channel: req.channel,
    user: req.jwt,
    payment: {
      id:        `PAY-${Date.now()}`,
      amount:    parseFloat(amount),
      currency,
      method,
      merchant:  merchant || 'unknown',
      status:    'processing',
      createdAt: new Date().toISOString(),
    },
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    console.error('[payments] JWE error:', err.message);
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

// GET /:id — detalle de un pago
app.get('/:id', validateJWT, validateClientInOdoo, validatePubKeyBinding, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const payload = {
    service: 'payments',
    channel: req.channel,
    user: req.jwt,
    payment: {
      id:        req.params.id,
      amount:    199.99,
      currency:  'USD',
      method:    'card',
      merchant:  'Acme Corp',
      last4:     '4242',
      status:    'settled',
      createdAt: '2026-05-29T14:20:00Z',
      settledAt: '2026-05-29T14:20:02Z',
    },
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

/* ── START ───────────────────────────────────────────── */
app.listen(3002, () => {
  console.log('💳 payments-service :3002');
  console.log(`   web-realm   → ${REALMS.web.issuer}`);
  console.log(`   mobile-realm→ ${REALMS.mobile.issuer}`);
});

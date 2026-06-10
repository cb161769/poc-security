const express = require('express');
const axios   = require('axios');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK } = require('jose');

const app = express();
app.use(express.json());
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

/* ── PUBKEY BINDING STORE ────────────────────────────── */
const pubKeyStore = new Map(); // Map<sub, { key: string, exp: number }>

function validatePubKeyBinding(req, res, next) {
  const pubKeyB64 = req.headers['x-client-public-key'];
  if (!pubKeyB64) return next();
  const sub = req.jwt.sub;
  const entry = pubKeyStore.get(sub);
  const now = Math.floor(Date.now() / 1000);
  if (!entry || now > entry.exp) {
    pubKeyStore.set(sub, { key: pubKeyB64, exp: req.jwt.exp });
    return next();
  }
  if (entry.key !== pubKeyB64)
    return res.status(403).json({ error: 'Clave de cliente no coincide con la registrada' });
  next();
}

/* ── IDEMPOTENCY STORE ───────────────────────────────── */
const IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;
const idempotencyStore = new Map();

function checkIdempotency(req, res, next) {
  const key = req.headers['x-idempotency-key'];
  if (!key) return res.status(400).json({ error: 'X-Idempotency-Key requerido' });
  const entry = idempotencyStore.get(key);
  if (entry) {
    return res.status(entry.statusCode)
      .set('Content-Type', entry.contentType)
      .set('X-Idempotency-Replayed', 'true')
      .send(entry.body);
  }
  const originalSend = res.send.bind(res);
  res.send = function(body) {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      idempotencyStore.set(key, {
        statusCode: res.statusCode,
        contentType: res.getHeader('Content-Type') || 'application/json',
        body,
      });
      setTimeout(() => idempotencyStore.delete(key), IDEMPOTENCY_TTL_MS);
    }
    return originalSend(body);
  };
  next();
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

      req.channel = channel;
      req.jwt = { sub: decoded.sub, email: decoded.email, roles, client_id: decoded.azp };
      next();
    }
  );
}

/* ── ODOO AUTHZ ──────────────────────────────────────── */
async function validateClientInOdoo(req, res, next) {
  try {
    const response = await axios.post(
      `${ODOO_URL}/api/validate-jwt-client`,
      { sub: req.jwt.sub, email: req.jwt.email, client_id: req.jwt.client_id, roles: req.jwt.roles },
      { headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || '' } }
    );
    if (!response.data || response.data.authorized !== true)
      return res.status(403).json({ error: 'Cliente no autorizado por Odoo' });
    req.client = response.data.client;
    next();
  } catch (error) {
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
app.post('/', validateJWT, validateClientInOdoo, validatePubKeyBinding, checkIdempotency, async (req, res) => {
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

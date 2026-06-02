const express = require('express');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK } = require('jose');

const app = express();
app.use(express.json());

/* ── CONFIG ─────────────────────────────────────────── */
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
        console.error(`[transfers][${channel}] JWT inválido:`, err.message);
        return res.status(401).json({ error: 'JWT inválido' });
      }

      const roles = decoded.realm_access?.roles || [];
      const allowed = ['user-api', 'admin-api', 'user-web', 'admin-web'];
      if (!roles.some(r => allowed.includes(r)))
        return res.status(403).json({ error: 'Rol insuficiente para el servicio de transferencias' });

      req.channel = channel;
      req.jwt = { sub: decoded.sub, email: decoded.email, roles, client_id: decoded.azp };
      next();
    }
  );
}

/* ── HELPER: JWE ─────────────────────────────────────── */
async function replyJWE(res, payload, pubKeyB64, channel) {
  const jwk = JSON.parse(Buffer.from(pubKeyB64, 'base64').toString());
  const pub  = await importJWK(jwk, 'RSA-OAEP-256');
  const jwe  = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', svc: 'transfers', channel })
    .encrypt(pub);
  res.set('Content-Type', 'application/jose').send(jwe);
}

/* ── ENDPOINTS ───────────────────────────────────────── */

// GET / — listar transferencias
app.get('/', validateJWT, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const payload = {
    service: 'transfers',
    channel: req.channel,
    user: req.jwt,
    data: [
      { id: 'TRF-001', amount: 500.00,  currency: 'USD', status: 'completed', to: 'ACC-9182', memo: 'Pago proveedor' },
      { id: 'TRF-002', amount: 1200.00, currency: 'USD', status: 'pending',   to: 'ACC-4471', memo: 'Nómina parcial' },
      { id: 'TRF-003', amount: 75.50,   currency: 'USD', status: 'failed',    to: 'ACC-0023', memo: 'Reembolso' },
    ],
    timestamp: new Date().toISOString(),
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    console.error('[transfers] JWE error:', err.message);
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

// POST / — crear transferencia
app.post('/', validateJWT, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const { amount, currency = 'USD', to, memo } = req.body;
  if (!amount || !to)
    return res.status(422).json({ error: 'amount y to son requeridos' });

  const payload = {
    service: 'transfers',
    channel: req.channel,
    user: req.jwt,
    transfer: {
      id:        `TRF-${Date.now()}`,
      amount:    parseFloat(amount),
      currency,
      to,
      memo:      memo || '',
      status:    'pending',
      createdAt: new Date().toISOString(),
    },
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    console.error('[transfers] JWE error:', err.message);
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

// GET /:id — detalle de una transferencia
app.get('/:id', validateJWT, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const payload = {
    service: 'transfers',
    channel: req.channel,
    user: req.jwt,
    transfer: {
      id:        req.params.id,
      amount:    320.00,
      currency:  'USD',
      status:    'completed',
      to:        'ACC-7734',
      memo:      'Pago de servicios',
      createdAt: '2026-05-28T10:15:00Z',
      completedAt: '2026-05-28T10:15:04Z',
    },
  };

  try {
    await replyJWE(res, payload, pubKey, req.channel);
  } catch (err) {
    res.status(400).json({ error: 'Clave de cliente inválida' });
  }
});

/* ── START ───────────────────────────────────────────── */
app.listen(3001, () => {
  console.log('💸 transfers-service :3001');
  console.log(`   web-realm   → ${REALMS.web.issuer}`);
  console.log(`   mobile-realm→ ${REALMS.mobile.issuer}`);
});

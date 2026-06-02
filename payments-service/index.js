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

/* ── HELPER: JWE ─────────────────────────────────────── */
async function replyJWE(res, payload, pubKeyB64, channel) {
  const jwk = JSON.parse(Buffer.from(pubKeyB64, 'base64').toString());
  const pub  = await importJWK(jwk, 'RSA-OAEP-256');
  const jwe  = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', svc: 'payments', channel })
    .encrypt(pub);
  res.set('Content-Type', 'application/jose').send(jwe);
}

/* ── ENDPOINTS ───────────────────────────────────────── */

// GET / — listar pagos
app.get('/', validateJWT, async (req, res) => {
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
app.post('/', validateJWT, async (req, res) => {
  const pubKey = req.headers['x-client-public-key'];
  if (!pubKey) return res.status(400).json({ error: 'X-Client-Public-Key requerido' });

  const { amount, currency = 'USD', method, merchant } = req.body;
  if (!amount || !method)
    return res.status(422).json({ error: 'amount y method son requeridos' });

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
app.get('/:id', validateJWT, async (req, res) => {
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

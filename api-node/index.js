const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK } = require('jose');

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
    issuer:  process.env.WEB_REALM_ISSUER  || 'http://localhost:8080/realms/web-realm',
    jwksUri: process.env.WEB_REALM_JWKS   || `${KEYCLOAK_BASE}/realms/web-realm/protocol/openid-connect/certs`,
    audience: 'web-api',
  },
  mobile: {
    issuer:  process.env.MOBILE_REALM_ISSUER  || 'http://localhost:8080/realms/mobile-realm',
    jwksUri: process.env.MOBILE_REALM_JWKS   || `${KEYCLOAK_BASE}/realms/mobile-realm/protocol/openid-connect/certs`,
    audience: 'mobile-api',
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
   PUBKEY BINDING STORE — first-use registration
   Map<sub, base64JWK> — persiste en memoria por lifetime del proceso
================================ */
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

      req.channel = channel;
      req.jwt = {
        sub:       decoded.sub,
        email:     decoded.email,
        roles:     decoded.realm_access?.roles || [],
        client_id: decoded.azp,
      };

      next();
    }
  );
}

/* ================================
   MIDDLEWARE: VALIDAR CLIENTE EN ODOO
================================ */
async function validateClientInOdoo(req, res, next) {
  try {
    const response = await axios.post(
      `${ODOO_URL}/api/validate-jwt-client`,
      { sub: req.jwt.sub, email: req.jwt.email, client_id: req.jwt.client_id, roles: req.jwt.roles },
      { headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || '' } }
    );

    const result = response.data;
    if (!result || result.authorized !== true) {
      return res.status(403).json({ error: 'Cliente no autorizado por Odoo' });
    }

    req.client = result.client;
    next();
  } catch (error) {
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
   START
================================ */
app.listen(3000, () => {
  console.log('🚀 Backend API seguro escuchando en puerto 3000');
  console.log(`   web-realm   → ${REALMS.web.issuer}`);
  console.log(`   mobile-realm→ ${REALMS.mobile.issuer}`);
});

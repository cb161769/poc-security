const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CompactEncrypt, importJWK } = require('jose');

const app = express();
app.use(express.json());

/* ================================
   CONFIG
================================ */
const ODOO_URL = process.env.ODOO_URL || 'http://odoo-server:8069';

const KEYCLOAK_ISSUER =
  process.env.KEYCLOAK_ISSUER ||
  'https://keycloak.midominio.com/realms/mobile-realm';

const KEYCLOAK_JWKS_URI =
  process.env.KEYCLOAK_JWKS_URI ||
  'https://keycloak.midominio.com/realms/mobile-realm/protocol/openid-connect/certs';

const JWT_AUDIENCE =
  process.env.JWT_AUDIENCE || 'mobile-api';

/* ================================
   JWKS CLIENT
================================ */
const jwks = jwksClient({
  jwksUri: KEYCLOAK_JWKS_URI,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

/* ================================
   MIDDLEWARE: VALIDAR JWT
================================ */
async function validateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token JWT requerido' });
  }

  const token = authHeader.replace('Bearer ', '');

  jwt.verify(
    token,
    getKey,
    {
      issuer: KEYCLOAK_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: ['RS256'],
      clockTolerance: 30,
    },
    (err, decoded) => {
      if (err) {
        console.error('JWT inválido:', err.message);
        return res.status(401).json({ error: 'JWT inválido' });
      }

      // Adjuntamos claims seguros al request
      req.jwt = {
        sub: decoded.sub,
        email: decoded.email,
        roles: decoded.realm_access?.roles || [],
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
      {
        sub: req.jwt.sub,
        email: req.jwt.email,
        client_id: req.jwt.client_id,
        roles: req.jwt.roles,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Secret': process.env.INTERNAL_SECRET || '',
        },
      }
    );

    const result = response.data;

    if (!result || result.authorized !== true) {
      return res.status(403).json({
        error: 'Cliente no autorizado por Odoo',
      });
    }

    // Cliente validado por negocio
    req.client = result.client;
    next();

  } catch (error) {
    console.error('Error Odoo:', error.message);
    return res.status(502).json({
      error: 'Error validando cliente en Odoo',
    });
  }
}

/* ================================
   ENDPOINT PROTEGIDO
================================ */
app.get(
  '/api/v1/data',
  validateJWT,
  validateClientInOdoo,
  async (req, res) => {
    const clientPubKeyB64 = req.headers['x-client-public-key'];

    if (!clientPubKeyB64) {
      return res.status(400).json({ error: 'X-Client-Public-Key requerido' });
    }

    const payload = {
      message: 'Datos protegidos recuperados con éxito',
      timestamp: new Date().toISOString(),
      user: {
        sub: req.jwt.sub,
        email: req.jwt.email,
        roles: req.jwt.roles,
      },
      client: req.client,
    };

    try {
      const jwk = JSON.parse(Buffer.from(clientPubKeyB64, 'base64').toString('utf8'));
      const publicKey = await importJWK(jwk, 'RSA-OAEP-256');

      const jwe = await new CompactEncrypt(
        new TextEncoder().encode(JSON.stringify(payload))
      )
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
        .encrypt(publicKey);

      res.set('Content-Type', 'application/jose');
      res.send(jwe);
    } catch (err) {
      console.error('JWE encrypt error:', err.message);
      res.status(400).json({ error: 'Clave de cliente inválida' });
    }
  }
);

/* ================================
   ENDPOINT INTERNO (KEYCLOAK → ODOO)
================================ */
app.post('/internal/validate-user', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post(`${ODOO_URL}/jsonrpc`, {
      jsonrpc: '2.0',
      method: 'call',
      params: {
        model: 'x_api_usuarios',
        method: 'validate_external_credentials',
        args: [username, password],
      },
    });

    if (response.data.result?.status === 'success') {
      res.json(response.data.result);
    } else {
      res.status(401).json({
        status: 'error',
        message: 'Credenciales inválidas en Odoo',
      });
    }
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Error de conexión con Odoo',
    });
  }
});

/* ================================
   START
================================ */
app.listen(3000, () => {
  console.log('🚀 Backend API seguro escuchando en puerto 3000');
});
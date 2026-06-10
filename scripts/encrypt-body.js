#!/usr/bin/env node
// Usage: node scripts/encrypt-body.js '<jwk-json>' '<payload-string>'
const path = require('path');
const { CompactEncrypt, importJWK } = require(
  path.join(__dirname, '../api-node/node_modules/jose')
);

const [,, jwkStr, payloadStr] = process.argv;
if (!jwkStr || !payloadStr) {
  console.error('Usage: encrypt-body.js <jwk-json> <payload-json>');
  process.exit(1);
}

(async () => {
  const jwk = JSON.parse(jwkStr);
  const key = await importJWK(jwk, 'RSA-OAEP-256');
  const jwe = await new CompactEncrypt(Buffer.from(payloadStr))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', dir: 'req' })
    .encrypt(key);
  process.stdout.write(jwe);
})().catch(e => { console.error(e.message); process.exit(1); });

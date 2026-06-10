# Security Backlog — Ionic App Security & Fixes

Estado al **2026-06-10**. Items completados marcados con ✅.

---

## ✅ Completado — P4 (Header Hardening)

- **✅ Eliminar X-Powered-By** — `app.disable('x-powered-by')` en api-node, transfers-service, payments-service
- **✅ Deshabilitar ETag en respuestas JWE** — `app.set('etag', false)` en los 3 servicios
- **✅ Cache-Control: no-store** — header forzado en cada respuesta `application/jose`

---

## ✅ Completado — P1a (Pubkey Binding)

- **✅ Bind client public keys server-side** — `validatePubKeyBinding` middleware en los 3 servicios  
  - Primera clave enviada por `sub` queda registrada con TTL = JWT `exp`
  - Request con clave diferente al binding registrado → 403
  - Endpoint `POST /api/v1/data/register-key` para registro explícito en mobile
  - Verificado: test 2/9 `test-attacks.sh` → PASS

---

## ✅ Completado — P1b (Anti-Replay)

- **✅ Idempotency Key en POST** — `checkIdempotency` middleware en transfers-service y payments-service
  - `X-Idempotency-Key` requerido en todos los POST
  - Mismo key dentro de 5 min → respuesta cacheada + `X-Idempotency-Replayed: true`
  - Verificado: tests 3 y 4/9 → PASS

---

## ✅ Completado — P1c (Odoo AuthZ)

- **✅ Autorización de negocio en transfers-service** — `validateClientInOdoo` copiado de api-node
- **✅ Autorización de negocio en payments-service** — mismo patrón
- **✅ Validación de monto máximo** — `MAX_TRANSFER_AMOUNT=10000`, `MAX_PAYMENT_AMOUNT=5000`
- **✅ Whitelist de métodos de pago** — `['card', 'ach', 'wire']`
- Verificado: tests 5, 6 y 7/9 → PASS

---

## ✅ Completado — P2 parcial (JWT + Channel)

- **✅ Strict JWT validation** — `iss`, `aud`, `exp`, roles verificados en los 3 servicios
- **✅ Cross-channel enforcement** — token web rechazado en mobile y viceversa → 401
- **✅ /internal/validate-user con JWT** — endpoint interno requiere JWT válido
- Verificado: test 8/9 → PASS

---

## ✅ Completado — Ops

- **✅ Docker .env / secretos externalizados** — `${VAR:-default}` en docker-compose.yml, `.env` gitignoreado
- **✅ Rate limiting verificado** — test 9/9 → 35 requests → 429 PASS
- **✅ TLS 1.2/1.3** — KONG_SSL_PROTOCOLS configurado, AEAD ciphers

---

## Pendiente — P2/P3 para producción

### P2 — Alta prioridad

- **Circuit Breaker** — sin Opossum/Resilience4j, caída de Odoo o Keycloak tumba todos los endpoints
  - Effort: 4–8h

- **Refresh Token Rotation + Revocación** — token comprometido válido hasta exp; falta blacklist Redis
  - Effort: 4–6h

- **Distributed Idempotency Store** — Map en memoria no persiste entre restarts; usar Redis con TTL
  - Effort: 2–4h

- **Token Storage (web)** — tokens en localStorage; migrar a `HttpOnly` cookies o Capacitor Secure Storage
  - Effort: 4–8h

### P3 — Media prioridad

- **Pubkey Store persistente** — Map en memoria se pierde en restart; persistir en Redis con TTL = JWT exp
  - Effort: 2–4h

- **Alerting + SIEM** — exportar eventos de seguridad (403 pubkey, Odoo 403, 429) a alertas
  - Effort: 3–6h

- **`secure-net: internal: true`** — Docker Compose tiene `internal: false` por conveniencia del POC
  - Effort: 30m (cambio + validación de conectividad)

- **CSP + SRI** — Content Security Policy + Subresource Integrity en `index.html`
  - Effort: 2–4h

- **Source maps deshabilitados en prod** — `angular.json` producción confirmar `sourceMap: false`
  - Effort: 1h

- **Dependency SCA en CI** — `npm audit` como gate en pipeline
  - Effort: 1–2h

---

## Test suites actuales

| Suite | Comando | Resultado |
|-------|---------|-----------|
| Funcional completo | `bash scripts/test-all.sh` | 33/33 PASS |
| Ataques negativos | `bash scripts/test-attacks.sh` | 17/17 PASS |
| Runtime Playwright | `node scripts/test-runtime-debug.js` | 10/10 PASS |

---

## Quick checklist PR a producción

- [ ] `secure-net: internal: true` en docker-compose.yml
- [ ] Secretos en vault (no .env)
- [ ] Pubkey store → Redis
- [ ] Idempotency store → Redis
- [ ] Circuit breaker en llamadas Odoo/Keycloak
- [ ] Refresh token rotation habilitado en Keycloak
- [ ] Token storage web → HttpOnly cookies
- [ ] `npm audit` sin hallazgos HIGH/CRITICAL
- [ ] Source maps deshabilitados
- [ ] CSP header presente y testeado

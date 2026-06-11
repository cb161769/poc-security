# Security Backlog — Ionic App Security & Fixes

Estado al **2026-06-11**. Items completados marcados con ✅.

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
- **✅ Source maps deshabilitados en producción** — `angular.json` build prod: `sourceMap: false`

---

## ✅ Completado — Android CI + Security Testing

- **✅ APK release firmado (Docker)** — `docker/android-build/` → Temurin JDK 21 + Gradle `assembleRelease` + keystore de test; APK 2.4 MB en volumen `android-apk`
- **✅ Suite de seguridad Android automatizada (30 fases MASVS v2)** — `docker/android-test-runner/test-android-docker.ps1`

  **Análisis estático + build hardening**
  - Phase 1: Static APK analysis — HTTP cleartext, allowBackup, debuggable, R8/ProGuard signal (MASVS-CODE, MASVS-NETWORK)
  - Phase 8: Network Security Config — cleartextTrafficPermitted, NSC file presence (MASVS-NETWORK-1)
  - Phase 13: Hardcoded secrets scan — Google API keys, AWS, JWT, Firebase, Stripe, PEM, OAuth, passwords en binario + DEX + assets (MASVS-STORAGE-1) **Critical**
  - Phase 16: APK Signature Schemes — V1/V2/V3/V4 detection via binary magic + apksigner (MASVS-CODE-1)
  - Phase 23: Native Library Audit — secrets en .so, JNI/RegisterNatives symbols (MASVS-CODE-1, MASVS-STORAGE-1)

  **Runtime checks — UI y sistema**
  - Phase 2: FLAG_SECURE attack — screencap + dumpsys window flags + screenrecord 2s (MASVS-PLATFORM-1) High
  - Phase 7: Log leak — logcat PID filter, ProGuard -assumenosideeffects (MASVS-CODE-1)
  - Phase 9: JDWP debugger attach — adb jdwp vs app PID (MASVS-RESILIENCE-3) **Critical**
  - Phase 25: Screen recording attack — adb screenrecord 2s contra app en foreground (MASVS-PLATFORM-1)
  - Phase 27: Clipboard leak — ClipboardManager patterns, password field protection (MASVS-PLATFORM-1)

  **Resiliencia y anti-tampering**
  - Phase 3: Root / Tamper Detection — test-keys build tags + su path strings (MASVS-RESILIENCE-1)
  - Phase 4: Frida detection — artifact strings en DEX (MASVS-RESILIENCE-2)
  - Phase 5: Signature — OS package install verification (MASVS-CODE-1)
  - Phase 22: Hook Detection — Frida/Xposed/LSPosed/Zygisk en DEX + /proc/maps + live frida attach si disponible (MASVS-RESILIENCE-2) **Critical**
  - Phase 28: Emulator detection — ro.kernel.qemu, ro.hardware, ro.build.fingerprint (MASVS-RESILIENCE-1)
  - Phase 29: Anti-Tamper — PackageManager sig check, Play Integrity API, checksum patterns (MASVS-RESILIENCE-2)

  **Platform security — IPC y componentes**
  - Phase 6: WebView debugging — static capacitor.config.json + CDP exploit via adb forward (MASVS-PLATFORM-2) **Critical**
  - Phase 10: Exported Component scan — pm dump scoped to pkg/Class: blocks (MASVS-PLATFORM-1)
  - Phase 11: ADB Backup — ALLOW_BACKUP ApplicationInfo flag (MASVS-STORAGE-1)
  - Phase 12: Tapjacking — filterTouchesWhenObscured en layouts (MASVS-PLATFORM-1)
  - Phase 15: WebView Hardening — UniversalFileAccess, MixedContent, addJavascriptInterface (MASVS-PLATFORM-2)
  - Phase 19: Deep Link Attack — scheme enumeration + am start fuzzing con path traversal/SQL/XSS payloads (MASVS-PLATFORM-1)
  - Phase 20: Broadcast Injection — exported receivers + unauthenticated am broadcast (MASVS-PLATFORM-1)
  - Phase 21: Content Provider Audit — content query unauthenticated en todas las autoridades (MASVS-PLATFORM-1) **Critical**
  - Phase 30: Intent Injection — am start con extras authenticated=true, role=admin, file:///etc/passwd (MASVS-PLATFORM-1)

  **Red y criptografía**
  - Phase 14: SSL Pinning — CertificatePinner, TrustKit, HostnameVerifier, NSC pin-set, onReceivedSslError (MASVS-NETWORK-2)
  - Phase 26: Certificate Transparency — requireCertificateTransparency NSC, user CA trust anchors (MASVS-NETWORK-1)

  **Storage runtime (requiere adb root)**
  - Phase 17: SharedPreferences Audit — EncryptedSharedPreferences vs plaintext, sensitive key names (MASVS-STORAGE-1,2) **Critical**
  - Phase 18: SQLite Audit — tablas, schema, columnas sensibles, SQLCipher detection (MASVS-STORAGE-1,2) **Critical**
  - Phase 24: Memory Scan — /proc/pid/mem scan para JWT, RSA keys, passwords en regiones heap (MASVS-STORAGE-2) **Critical**

- **✅ Reporte HTML MASVS v2** — `docs/android-test-reports/android-security-report.html`
  - Columnas: Status | Severity (Critical/High/Medium/Low/Info badges) | MASVS control | Check + Evidence + Recommendation
  - Stats: pass/fail/warn, Critical count, High fail count, duración total
- **✅ Exportación de reportes** — HTML auto-generado; build problems en `docs/android-build-reports/`
- **✅ Perfil Docker Compose `android-tests`** — emulador `budtmo/docker-android:emulator_14.0` + build + runner con dependencias ordenadas

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

- ~~**Source maps deshabilitados en prod**~~ — **✅ Hecho** (`angular.json` prod: `sourceMap: false`)

- **Dependency SCA en CI** — `npm audit` como gate en pipeline
  - Effort: 1–2h

---

## Test suites actuales

| Suite | Comando | Resultado |
|-------|---------|-----------|
| Funcional completo | `bash scripts/test-all.sh` | 33/33 PASS |
| Ataques negativos | `bash scripts/test-attacks.sh` | 17/17 PASS |
| Runtime Playwright | `node scripts/test-runtime-debug.js` | 10/10 PASS |
| Android MASVS v2 | `docker compose --profile android-tests up` | 26 Pass / 0 Fail / 9 Warn — 35 checks en 54s |

### Android — detalle de los 9 warnings (no son fallos, son mejoras recomendadas)

| Fase | Warning | Acción recomendada |
|------|---------|-------------------|
| Ph.14 | WebView `onReceivedSslError` override presente | Verificar que llama `handler.cancel()` no `handler.proceed()` |
| Ph.14 | Sin SSL/cert pinning | Implementar `CertificatePinner` en OkHttp o NSC `<pin-set>` con SHA-256 real |
| Ph.15 | `setAllowUniversalAccessFromFileURLs`, `setAllowFileAccessFromFileURLs`, `addJavascriptInterface`, `setAllowFileAccess` | Auditar bridge Capacitor; estos flags los establece el runtime de Ionic |
| Ph.25 | Screen record 5.9 KB (pequeño) | Verificar en dispositivo físico que el video sale en negro (FLAG_SECURE efectivo) |
| Ph.26 | Sin `requireCertificateTransparency` | Añadir en NSC para producción |
| Ph.27 | `ClipboardManager` accedido | Confirmar que campos de contraseña tienen `inputType=textPassword` |
| Ph.28 | Sin strings de detección de emulador en DEX | Añadir check `ro.kernel.qemu` en SecurityManager Java |

---

## Quick checklist PR a producción

- [x] Source maps deshabilitados (`angular.json` prod)
- [x] Android security test suite automatizada (Docker CI)
- [ ] `secure-net: internal: true` en docker-compose.yml
- [ ] Secretos en vault (no .env)
- [ ] Pubkey store → Redis
- [ ] Idempotency store → Redis
- [ ] Circuit breaker en llamadas Odoo/Keycloak
- [ ] Refresh token rotation habilitado en Keycloak
- [ ] Token storage web → HttpOnly cookies
- [ ] `npm audit` sin hallazgos HIGH/CRITICAL
- [ ] CSP header presente y testeado

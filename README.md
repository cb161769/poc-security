# POC Seguridad API — Microservicios con JWT + JWE

Prueba de concepto de arquitectura de seguridad para APIs móviles y web.  
Implementa autenticación federada, cifrado de payload de extremo a extremo y autorización de negocio.

### Animaciones interactivas

| Animación / Presentación | Descripción |
|--------------------------|-------------|
| [docs/request-flow.html](docs/request-flow.html) | Flujo paso a paso: PKCE → JWT → RSA keygen → Kong → JWKS → Odoo AuthZ → JWE encrypt → decrypt (11 pasos animados) |
| [docs/stride.html](docs/stride.html) | Modelo de amenazas STRIDE: vectores de ataque y contramedidas implementadas por categoría |
| [docs/attack-repudiation.html](docs/attack-repudiation.html) | Presentación PPT (12 slides): 8 categorías de ataque, controles implementados, estado de mitigación y próximos pasos — apta para revisar con el equipo de seguridad |

> Abre los archivos directamente en el navegador — no requieren servidor.  
> **Navegación en la presentación:** teclas `←` `→` o barra espaciadora.

---

## Arquitectura

```
App Ionic (Web / Mobile)
  │
  ├── Keycloak 26 ──── Autenticación PKCE + JWT RS256
  │     ├── web-realm   (aud: ["web-api","account"]   · TTL: 5 min)
  │     └── mobile-realm (aud: ["mobile-api","account"] · TTL: 5 min)
  │
  └── Kong 3.5 ──────── Perímetro TLS + Rate Limiting
        ├── /api/v1/web/**    → 60 req/min · X-Channel: web
        └── /api/v1/mobile/** → 30 req/min · X-Channel: mobile
              │
              ├── api-node:3000       Identity Bridge + Odoo AuthZ (POST /api/validate-jwt-client)
              ├── transfers-service:3001  Transferencias (JWT + rol, sin Odoo)
              └── payments-service:3002   Pagos (JWT + rol, sin Odoo)
                    │
                    └── Odoo 17 ─── Autorización de negocio (x_api_clientes)
                          └── PostgreSQL 15
```

**Seguridad end-to-end:**
- JWT firmado RS256, validado con JWKS de Keycloak
- Respuestas cifradas con **JWE RSA-OAEP-256 + A256GCM**
- Clave privada del cliente: `extractable: false` en web (efímera), persistible en mobile
- Rate limiting diferenciado por canal
- Token expiry con alerta automática en la app

---

## Requisitos previos

| Herramienta | Versión mínima | Descarga |
|-------------|---------------|---------|
| Docker Desktop | 4.x | https://www.docker.com/products/docker-desktop |
| Node.js | 18 LTS o superior | https://nodejs.org |
| Python | 3.8+ | https://www.python.org |
| OpenSSL | 1.1.1+ | Incluido en Git for Windows / macOS / Linux |
| Git | cualquiera | https://git-scm.com |

**Python — librería requerida para el script de pruebas:**
```bash
pip install cryptography
```

**Windows:** usar [Git Bash](https://git-scm.com/download/win) para ejecutar los scripts `.sh`.  
**macOS/Linux:** bash nativo.

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone <URL_DEL_REPO> poc-security
cd poc-security
```

### 2. Setup automático (recomendado)

Ejecuta el script de configuración inicial. Hace todo en orden:

```bash
bash scripts/setup.sh
```

Esto realiza automáticamente:
- Genera certificados TLS autofirmados (`shared-keys/`)
- Levanta todos los contenedores Docker
- Espera a que Keycloak y Odoo estén listos
- Crea los reinos, clientes, usuarios y audience mappers en Keycloak
- Inicializa la base de datos de Odoo con el addon personalizado
- Crea los registros de autorización en Odoo para el usuario de prueba
- Instala dependencias de la app Ionic

**Tiempo estimado: 3–5 minutos** (descarga de imágenes Docker la primera vez: ~10 min)

---

### 3. Setup manual (paso a paso)

Si prefieres hacer el setup paso a paso o el script automático falla:

#### 3.1 Generar certificados TLS

```bash
mkdir -p shared-keys

# CA autofirmada
openssl genrsa -out shared-keys/ca.key 4096
openssl req -new -x509 -days 825 -key shared-keys/ca.key \
  -subj "/C=DO/O=InternalCA/OU=Security/CN=internal-ca" \
  -out shared-keys/ca.pem

# Certificado del servidor (Kong)
openssl genrsa -out shared-keys/kong.key 4096
openssl req -new -key shared-keys/kong.key \
  -subj "/C=DO/O=API/OU=Gateway/CN=localhost" -out /tmp/kong.csr
openssl x509 -req -in /tmp/kong.csr -CA shared-keys/ca.pem \
  -CAkey shared-keys/ca.key -CAcreateserial -days 825 \
  -out shared-keys/fullchain.pem

# Par RSA para JWE (key-rotator lo renueva automáticamente cada 24h)
openssl genrsa -out shared-keys/priv.pem 2048
openssl rsa -in shared-keys/priv.pem -pubout -out shared-keys/pub.pem
date > shared-keys/last_rotation.txt
```

#### 3.2 Levantar Docker Compose

```bash
docker compose up -d --build
```

Verifica que todos los contenedores estén corriendo:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Deberías ver:
```
NAMES                 STATUS
kong-gateway          Up X seconds (healthy)
keycloak-server       Up X seconds
api-node              Up X seconds
transfers-service     Up X seconds
payments-service      Up X seconds
odoo-server           Up X seconds
db-poc                Up X seconds (healthy)
key-rotator           Up X seconds
certbot-service       Up X seconds
```

#### 3.3 Configurar Keycloak

Espera a que Keycloak esté listo (puede tomar 60–90 segundos):

```bash
# Esperar hasta que responda
until curl -sf http://localhost:8080/realms/master; do sleep 5; done
```

**Obtener token de admin:**
```bash
ADMIN_TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Crear web-realm** (mobile-realm se importa automáticamente desde `keycloak-config/`):
```bash
curl -s -X POST "http://localhost:8080/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @keycloak-config/realm-web.json
# Respuesta esperada: HTTP 201
```

**Crear usuario de prueba en mobile-realm:**
```bash
curl -s -X POST "http://localhost:8080/admin/realms/mobile-realm/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "username":"testuser","email":"testuser@poc.com",
    "firstName":"Test","lastName":"User",
    "emailVerified":true,"enabled":true,"requiredActions":[],
    "credentials":[{"type":"password","value":"Test1234!","temporary":false}]
  }'

# Asignar rol user-api
USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/mobile-realm/users?username=testuser" \
  | python -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

ROLE_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/mobile-realm/roles/user-api" \
  | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

curl -s -X POST \
  "http://localhost:8080/admin/realms/mobile-realm/users/$USER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "[{\"id\":\"$ROLE_ID\",\"name\":\"user-api\"}]"

# Agregar audience mapper (mobile-api)
CLIENT_UUID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/mobile-realm/clients?clientId=mobile-app-client" \
  | python -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X POST \
  "http://localhost:8080/admin/realms/mobile-realm/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name":"mobile-api-audience","protocol":"openid-connect",
    "protocolMapper":"oidc-audience-mapper",
    "config":{"included.custom.audience":"mobile-api","access.token.claim":"true","id.token.claim":"false"}
  }'
```

**Crear usuario de prueba en web-realm** (mismo proceso):
```bash
# Reemplaza "mobile-realm" por "web-realm", "user-api" por "user-web",
# "mobile-app-client" por "web-app-client", "mobile-api" por "web-api"
# en los comandos anteriores.
```

#### 3.4 Inicializar Odoo

```bash
# Crear la base de datos e instalar el addon
docker exec odoo-server sh -c \
  "odoo --stop-after-init -d pocdb --init=api_security_poc \
   --db_host=db-poc --db_port=5432 \
   --db_user=admin_seguro --db_password=password_2026"

# Reiniciar Odoo para que use pocdb
docker compose restart odoo
sleep 10
```

**Crear registros de autorización en Odoo:**

```bash
# Obtener los SUB de ambos usuarios
WEB_TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

WEB_SUB=$(echo $WEB_TOKEN | python -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
print(json.loads(base64.b64decode(t))['sub'])
")

MOB_TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

MOB_SUB=$(echo $MOB_TOKEN | python -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
print(json.loads(base64.b64decode(t))['sub'])
")

# Autenticarse en Odoo y crear registros
docker exec odoo-server sh -c "
curl -s -c /tmp/c.txt -X POST 'http://localhost:8069/web/session/authenticate' \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":{\"db\":\"pocdb\",\"login\":\"admin\",\"password\":\"admin\"}}' > /dev/null

curl -s -b /tmp/c.txt -X POST 'http://localhost:8069/web/dataset/call_kw' \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":{\"model\":\"x_api_clientes\",\"method\":\"create\",\"args\":[{\"name\":\"Test User Web\",\"sub\":\"$WEB_SUB\",\"email\":\"testuser@poc.com\",\"client_id\":\"web-app-client\",\"active\":true}],\"kwargs\":{}}}' > /dev/null

curl -s -b /tmp/c.txt -X POST 'http://localhost:8069/web/dataset/call_kw' \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":{\"model\":\"x_api_clientes\",\"method\":\"create\",\"args\":[{\"name\":\"Test User Mobile\",\"sub\":\"$MOB_SUB\",\"email\":\"testuser@poc.com\",\"client_id\":\"mobile-app-client\",\"active\":true}],\"kwargs\":{}}}' > /dev/null
"
```

#### 3.5 Instalar dependencias de la Ionic App

```bash
cd ionic-app/poc-security
npm install
```

---

## Uso

### Iniciar la app Ionic

```bash
cd ionic-app/poc-security
npm start
# Abre: http://localhost:4200
```

### Credenciales de prueba

| Campo | Valor |
|-------|-------|
| Usuario | `testuser` |
| Contraseña | `Test1234!` |
| Keycloak admin | `admin` / `admin` |
| Odoo admin | `admin` / `admin` |

### Flujo de la app

1. **Tab "Identidad" 🛡️** → Login con `testuser / Test1234!`
   - Muestra el canal detectado (Web/Mobile), el reino y la estrategia JWE
   - Timer de expiración de sesión con alerta automática
   - Botón "Solicitar datos cifrados" para probar el endpoint de identidad

2. **Tab "Transferencias" 💸** → (requiere login)
   - Carga la lista de transferencias recientes (JWE descifrado)
   - Formulario para crear una nueva transferencia
   - Muestra el token JWE cifrado recibido

3. **Tab "Pagos" 💳** → (requiere login)
   - Carga la lista de pagos recientes (JWE descifrado)
   - Formulario para crear un nuevo pago (tarjeta / ACH)
   - Muestra el token JWE cifrado recibido

---

## Debugging en runtime (app Ionic en el navegador)

Técnicas para modificar variables y estados en vivo desde las DevTools de Chrome/Edge sin tocar código.

### 1. Breakpoint + consola del debugger (más potente)

Abre **DevTools → Sources**, habilita source maps (`Enable JavaScript source maps`), busca el archivo con `Ctrl+P`:

```
Ctrl+P → "auth.service.ts"    # o crypto.service.ts, api.service.ts
```

Haz click en el número de línea para poner un breakpoint. Cuando el código se pause, la consola tiene acceso completo al scope:

```javascript
// Con ejecución pausada en login():
this.token = "eyJhbGci..."         // reemplazar token
decoded.exp = Date.now()/1000 + 9999  // extender expiración sin re-firmar
channel = 'mobile'                 // cambiar canal en scope local
```

O añade `debugger;` temporalmente en el código donde necesites pausar.

### 2. Acceder a servicios Angular desde la consola

```javascript
// Obtener cualquier componente
const el  = document.querySelector('app-tab1')   // o 'app-root', 'ion-app'
const comp = ng.getComponent(el)

// Leer / escribir propiedades del componente
comp.isLoggedIn               // leer
comp.isLoggedIn = false       // escribir (fuerza estado visual)
comp.channel = 'mobile'       // cambiar canal
ng.applyChanges(comp)         // forzar detección de cambios en la UI

// Obtener el injector para acceder a servicios singleton
const injector = ng.getInjector(el)
```

### 3. Interceptar y modificar respuestas de la API (monkey-patch fetch)

```javascript
// Ver el JWE crudo antes de que Angular lo procese
const _fetch = window.fetch
window.fetch = async (...args) => {
  const res = await _fetch(...args)
  if (String(args[0]).includes('localhost:8000')) {
    const clone = res.clone()
    clone.text().then(body => console.log('Kong response:', args[0], '\n', body.slice(0,120)))
  }
  return res
}

// Simular error 403 de Odoo en transfers
window.fetch = async (...args) => {
  if (String(args[0]).includes('/transfers'))
    return new Response(JSON.stringify({ error: 'Cliente no autorizado por Odoo' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } })
  return _fetch(...args)
}

// Restaurar fetch original
window.fetch = _fetch
```

### 4. Corromper el JWE para probar manejo de errores

Con un breakpoint en `crypto.service.ts` dentro del método de descifrado:

```javascript
// Corromper el authentication tag (últimos 5 chars) → compactDecrypt debe lanzar error
> jweToken = jweToken.slice(0, -5) + 'XXXXX'

// Truncar el JWE a 3 partes → estructura inválida
> jweToken = jweToken.split('.').slice(0, 3).join('.')

// Sustituir con JWE de otro canal → debe dar 401 en el servicio
> jweToken = tokenGuardadoDeOtroCanal
```

### 5. Inspeccionar / modificar el JWT en storage

```javascript
// Ver qué hay en storage
Object.entries(localStorage)
Object.entries(sessionStorage)

// Inspeccionar claims del token guardado (sin verificar firma)
const raw = localStorage.getItem('access_token')   // ajustar key según la app
if (raw) {
  const payload = JSON.parse(atob(raw.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')))
  console.table(payload)
  console.log('Expira:', new Date(payload.exp * 1000))
  console.log('TTL restante:', payload.exp - Date.now()/1000, 'seg')
}

// Forzar expiración inmediata para probar el timer de sesión de la UI
// (solo afecta la lectura del storage, el servidor seguirá rechazando con 401)
const parts = raw.split('.')
const p = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))
p.exp = Math.floor(Date.now()/1000) - 1   // ya expirado
// No se puede re-firmar, pero sirve para probar el comportamiento de la UI
```

### 6. Simular canal mobile desde el navegador web

```javascript
// Sobreescribir detección de Capacitor antes de que Angular arranque
// (ejecutar en la consola ANTES de que cargue la app, o en el snippet de Sources)
Object.defineProperty(window, 'Capacitor', {
  get: () => ({ isNativePlatform: () => true, getPlatform: () => 'android' }),
  configurable: true
})
location.reload()   // recargar para que platform.service.ts lo detecte al init

// Restaurar
delete window.Capacitor
location.reload()
```

### Referencia rápida de comandos de consola

| Objetivo | Comando |
|----------|---------|
| Obtener componente | `ng.getComponent(document.querySelector('app-tab1'))` |
| Forzar re-render | `ng.applyChanges(comp)` |
| Ver árbol de componentes | `ng.getOwningComponent(el)` |
| Obtener injector | `ng.getInjector(document.querySelector('app-root'))` |
| Tiempo restante del JWT | `payload.exp - Date.now()/1000` |
| Interceptar fetch | `window.fetch = async (...a) => { /* ... */; return originalFetch(...a) }` |
| Restaurar fetch | `window.fetch = _fetch` (guardar referencia antes) |

> **Nota:** `ng.getComponent()` solo está disponible en builds de desarrollo (`ng serve`). En producción (`ng build`) Angular elimina estos helpers. Los monkey-patches de `fetch` se resetean al recargar la página.

## Hardening against runtime tampering

Practical steps to reduce the attack surface exposed by in-browser runtime debugging and monkey-patching.

- **Build without source-maps for production** — prevents easy mapping from minified code to TS sources:

```bash
# production build (no source maps)
ng build --configuration production --source-map=false
```

- **Enable Angular production mode** (already done by production build). Ensure `enableProdMode()` is used in `main.ts` for production bundles.

- **Remove dev-only helpers** — do not expose Angular devtools globals in production (handled by production build/minification).

- **Server-side hardening (Express / Node)** — enforce headers and disable dev leaks:

```js
// in your Express app
app.disable('x-powered-by');
app.set('etag', false); // avoid leaking ciphertext size
res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
```

- **Content Security Policy & SRI** — set strict `Content-Security-Policy` headers and use Subresource Integrity for any third-party scripts to reduce XSS/monkey-patch risk.

- **Protect tokens & keys in the client** — avoid `localStorage` for long-lived tokens on web. Prefer secure, `HttpOnly` cookies or short-lived access tokens + refresh tokens stored safely on mobile (Keychain/Keystore).

- **Do not trust the client for security** — assume an attacker can modify runtime state (DevTools, `fetch` monkey-patches, altered inputs). Enforce every business rule and authorization check on the server (identity, role, balance, recipient allow-list, per-user limits).

- **Bind client public keys server-side** — when the client sends `X-Client-Public-Key`, require a server-side binding step (store ephemeral pubkey per session/sub) and refuse to encrypt to arbitrary, unbound keys.

- **Sign important responses** — include a server-side signature (JWS) over critical fields (tx id, amount, recipient, timestamp) inside the JWE so tampering in transit is detectable.

- **Handle JWE/JWT errors safely** — on decryption or verification failures return generic errors and do not leak internal details or stack traces.

- **Operational measures** — enforce rate limits, anomaly detection, and log suspicious activity; keep `jose`/JWT libraries up-to-date and rotate keys regularly.

These measures make runtime tampering harder and reduce the value of DevTools-based attacks, but they cannot fully prevent a malicious user who controls their browser. The authoritative controls must always be on the server.

---

## Ejecutar las pruebas

### Suite de integración (infraestructura + API)

```bash
bash scripts/test-all.sh
```

**Resultado esperado: 33/33 PASS**

Cubre:
- Infraestructura (7 contenedores)
- Keycloak (OIDC discovery, tokens, audience claims)
- Clave RSA (simulación WebCrypto)
- Kong (security headers, correlation ID, proxy)
- 6 flujos JWE (3 servicios × 2 canales)
- 5 rechazos de seguridad (cross-channel, sin token, firma inválida)
- 4 endpoints POST (crear transferencia/pago por canal)

### Suite de runtime debugging (Playwright)

Valida las técnicas de debugging documentadas en la sección [Debugging en runtime](#debugging-en-runtime-app-ionic-en-el-navegador) contra la app en vivo.

**Prerequisito:** la app Ionic debe estar corriendo en `http://localhost:4200`.

```bash
# Instalar dependencias (solo la primera vez — desde la raíz del proyecto)
npm install

# Descargar el binario de Chromium (solo la primera vez)
npx playwright install chromium

# Ejecutar
node scripts/test-runtime-debug.js
# o con el script npm:
npm run test:runtime
```

**Resultado esperado: 10/10 PASS**

| # | Test | Qué valida |
|---|------|-----------|
| 1 | `ng.getComponent()` | Angular debug API disponible en dev build |
| 2 | `ng.applyChanges()` | Force change detection sin error |
| 3 | `ng.getInjector()` | Acceso al DI container en runtime |
| 4 | JWT en storage | JWT en memoria del servicio (no expuesto en localStorage) |
| 5 | Monkey-patch fetch | Instalación y restauración del interceptor `window.fetch` |
| 6 | fetch mock 403 | Simulación de error Odoo en `/transfers` |
| 7 | Capacitor simulation | Override de `isNativePlatform` / `getPlatform` |
| 8 | Modificar componente | `ng.getComponent('app-tab1')` → `Tab1Page` con 13 props |
| 9 | App carga | 3 tabs visibles: Identidad / Transferencias / Pagos |
| 10 | — | (incluido en checks combinados de los anteriores) |

> Los screenshots de cada paso se guardan en `docs/debug-screenshots/`.  
> La suite usa Chromium (headless). Si el navegador no está disponible: `npx playwright install chromium`.

---

## Endpoints disponibles

### Kong (puerto 8000)

| Ruta | Servicio | Canal | Rate Limit |
|------|----------|-------|-----------|
| `GET /api/v1/web/api/v1/data` | api-node | web | 60/min |
| `GET /api/v1/mobile/api/v1/data` | api-node | mobile | 30/min |
| `GET /api/v1/web/transfers` | transfers-service | web | 60/min |
| `POST /api/v1/web/transfers` | transfers-service | web | 60/min |
| `GET /api/v1/mobile/transfers` | transfers-service | mobile | 30/min |
| `POST /api/v1/mobile/transfers` | transfers-service | mobile | 30/min |
| `GET /api/v1/web/payments` | payments-service | web | 60/min |
| `POST /api/v1/web/payments` | payments-service | web | 60/min |
| `GET /api/v1/mobile/payments` | payments-service | mobile | 30/min |
| `POST /api/v1/mobile/payments` | payments-service | mobile | 30/min |

**Headers requeridos en todas las peticiones:**
```
Authorization: Bearer <JWT>
X-Client-Public-Key: <base64( JSON(JWK) )>   ← clave pública RSA como objeto JWK serializado en JSON y luego base64
```

**Formato de respuesta:** `Content-Type: application/jose; charset=utf-8` (JWE compact — 5 partes separadas por `.`)

**Headers de respuesta reales (observados en vivo):**
```
X-Request-Id: <uuid>              ← correlation ID (echo del plugin Kong correlation-id)
X-Kong-Request-Id: <hex>          ← ID interno de Kong (diferente al anterior)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=()
Via: kong/3.5.0
X-Powered-By: Express             ⚠ fuga de framework — eliminar en producción
ETag: W/"<hex>-<hash>"            ⚠ revela tamaño del JWE cifrado
```

**JWE Protected Header real (decodificado):**
```json
{ "alg": "RSA-OAEP-256", "enc": "A256GCM", "svc": "data|transfers|payments", "channel": "web|mobile" }
```

### Servicios internos (solo accesibles en secure-net)

| URL | Puerto |
|-----|--------|
| Keycloak | http://localhost:8080 |
| Odoo | http://localhost:8069 |
| Kong Admin API | http://localhost:8001 (solo loopback) |

---

## Estructura del proyecto

```
poc-security/
├── api-node/              # Identity Bridge: JWT + Odoo AuthZ + JWE
├── transfers-service/     # Microservicio de transferencias
├── payments-service/      # Microservicio de pagos
├── ionic-app/
│   └── poc-security/      # App Ionic/Angular (web + mobile)
│       └── src/app/
│           ├── services/
│           │   ├── auth.service.ts      # Login Keycloak + JWT expiry
│           │   ├── api.service.ts       # Llamadas JWE a los servicios
│           │   ├── crypto.service.ts    # WebCrypto RSA-OAEP + compactDecrypt
│           │   └── platform.service.ts  # Detección web vs Capacitor
│           ├── tab1/     # Login + Identity + Timer de sesión
│           ├── tab2/     # Transferencias
│           └── tab3/     # Pagos
├── odoo-custom-addons/
│   └── api_security_poc/  # Addon Odoo: x_api_clientes + HTTP controller
├── keycloak-config/       # realm-mobile.json + realm-web.json (auto-import)
├── shared-keys/           # Certificados TLS + claves RSA (generados, no en repo)
├── scripts/
│   ├── setup.sh           # Script de configuración inicial
│   ├── test-all.sh        # Suite de pruebas (33 tests)
│   └── killswitch.sh      # Bloqueo de emergencia vía Kong
├── docker-compose.yml
└── kong.yml               # Rutas + plugins declarativos
```

---

## Solución de problemas

### Kong no inicia

```bash
docker logs kong-gateway --tail=30
```

Causas comunes:
- `shared-keys/` no existe o faltan certificados → ejecutar paso 3.1
- Puerto 8000 o 8443 en uso → cambiar en `docker-compose.yml`

### Keycloak demora mucho

Normal la primera vez (descarga imagen 500MB + inicializa DB).  
Verifica con: `docker logs keycloak-server --tail=20`

### Error "JWT inválido" en la app

1. Verifica que el usuario tenga el audience mapper correcto en Keycloak
2. Verifica que el INTERNAL_SECRET coincida entre api-node y Odoo
3. El realm-issuer debe ser `http://localhost:8080/realms/...` (no el hostname interno de Docker)

### Error "Cliente no autorizado por Odoo"

El `sub` del JWT no tiene registro en `x_api_clientes`. Repetir el paso 3.4 de Odoo.

### Odoo no responde

```bash
docker logs odoo-server --tail=30
docker compose restart odoo
```

### App Ionic no compila

```bash
cd ionic-app/poc-security
rm -rf node_modules
npm install
npm start
```

### Reiniciar todo desde cero

```bash
docker compose down -v        # Elimina contenedores Y volúmenes (borra datos)
rm -rf shared-keys/           # Elimina certificados
bash scripts/setup.sh         # Volver a configurar
```

---

## Seguridad — Notas para producción

> Este es un POC con configuraciones simplificadas. Antes de llevar a producción:

| Item | POC | Producción |
|------|-----|------------|
| Credenciales DB | Hardcodeadas en docker-compose | Docker Secrets / Vault |
| Keycloak admin | `admin/admin` | Contraseña fuerte + MFA |
| `secure-net` | `internal: false` | `internal: true` |
| Certificados | Autofirmados | Let's Encrypt / CA corporativa |
| Logging | Console stdout | ELK / Loki estructurado |
| Rate limiting | Policy local (un nodo) | Redis backend (multi-nodo) |
| `/internal/validate-user` | **Expuesto vía Kong sin JWT** (accesible en `/api/v1/mobile/internal/validate-user`) | Añadir middleware JWT + `X-Internal-Secret` |
| `X-Powered-By: Express` | **Leakage de framework activo** | Añadir `app.disable('x-powered-by')` en todos los servicios Node |
| ETag en respuestas JWE | **Revela tamaño del payload cifrado** | Deshabilitar ETag en rutas `/api/...` |
| Odoo AuthZ | Solo en api-node; transfers/payments validan solo JWT + rol | Agregar validación Odoo en los tres servicios |
| Vault token | Archivo plano en disco | AppRole + TTL corto |

---

## Tecnologías

| Componente | Tecnología |
|-----------|-----------|
| Gateway | Kong 3.5 (OSS) |
| Identidad | Keycloak 26 |
| Backend | Node.js 20 + Express |
| Autorización | Odoo 17 (addon custom) |
| Base de datos | PostgreSQL 15 |
| App | Ionic 8 + Angular 20 + Capacitor 8 |
| Cifrado payload | JWE RSA-OAEP-256 + A256GCM (librería `jose` v5) |
| Auth JWT | RS256 + JWKS (librería `jsonwebtoken` + `jwks-rsa`) |

# POC Seguridad API — Microservicios con JWT + JWE

Prueba de concepto de arquitectura de seguridad para APIs móviles y web.  
Implementa autenticación federada, cifrado de payload de extremo a extremo y autorización de negocio.

### Animaciones interactivas

| Animación / Presentación | Descripción |
|--------------------------|-------------|
| [docs/index.html](docs/index.html) | **Presentación ejecutiva** (CTO/CSO): resumen ejecutivo, arquitectura con Keycloak, STRIDE, controles en lenguaje de negocio, resultados 98/98, roadmap · Apéndice técnico incluido |
| [docs/arch.html](docs/arch.html) | **Architecture Review** (Chief Architect): diagrama C2, ADRs con rationale, cadena de middlewares y por qué el orden importa, gestión de estado y escalabilidad, patrones de seguridad, gap analysis con esfuerzo |
| [docs/request-flow.html](docs/request-flow.html) | Flujo paso a paso: PKCE → JWT → RSA keygen → Kong → JWKS → Odoo AuthZ → JWE encrypt → decrypt (11 pasos animados) |
| [docs/stride.html](docs/stride.html) | Modelo de amenazas STRIDE: vectores de ataque y contramedidas implementadas por categoría |
| [docs/attack-repudiation.html](docs/attack-repudiation.html) | Detalle de ataques repudiados: 8 categorías, controles implementados y estado de mitigación |

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
pip3 install cryptography
```

**Windows:** usar [Git Bash](https://git-scm.com/download/win) para ejecutar los scripts `.sh`.  
**macOS/Linux:** bash nativo. Los scripts usan `python3` — disponible con cualquier instalación estándar de Python 3.

> **macOS con Apple Silicon (M1/M2/M3/M4):** Docker Desktop for Mac incluye soporte multi-arch; las imágenes (Keycloak, Kong, Odoo) tienen builds ARM64 nativos.

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

### 4. Features de seguridad avanzada

#### 4.1 Keycloak — infraestructura endurecida

Todo está configurado automáticamente al levantar el stack. Verifica que Keycloak haya arrancado en modo producción (`start`, no `start-dev`) y esté saludable antes de que api-node, transfers y payments inicien:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep keycloak
# Esperado: keycloak-server   Up X seconds (healthy)
```

Lo que está configurado en `docker-compose.yml` y los realm JSON:

| Control | Valor |
|---------|-------|
| Modo de arranque | `start --http-enabled=true --import-realm` (producción, no dev) |
| Schema DB Keycloak | `KC_DB_SCHEMA: keycloak` — aislado del schema `public` de Odoo |
| Healthcheck | `GET /health/ready` — los 3 servicios backend esperan `(healthy)` |
| Token TTL | 300 s (5 min) |
| Sesión idle | 1800 s (30 min) |
| Brute-force protection | Bloqueo tras 5 intentos fallidos, espera máx 15 min |
| Pool DB Keycloak | min 5 / max 20 conexiones |

Si Keycloak no llega a `(healthy)` después de 2–3 minutos:

```bash
docker logs keycloak-server --tail 40
# Causa frecuente: KC_DB_SCHEMA "keycloak" no existe aún.
# Solución: el archivo docker/db-init/01-keycloak-schema.sql
# se ejecuta automáticamente en el primer arranque de db-poc.
# Si db-poc ya tenía datos, ejecutar manualmente:
docker exec db-poc psql -U admin_seguro -d postgres -c "CREATE SCHEMA IF NOT EXISTS keycloak;"
docker compose restart keycloak
```

#### 4.2 Enforcement de versión de app

Kong rechaza cualquier petición sin el header `X-App-Version: 1.0.0` con **HTTP 426 Upgrade Required**. No requiere configuración adicional — ya está activo en todas las rutas.

Verificar que funciona:

```bash
# Sin header → 426
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/mobile/api/v1/data
# → 426

# Versión incorrecta → 426
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-App-Version: 9.9.9" \
  http://localhost:8000/api/v1/mobile/api/v1/data
# → 426

# Versión correcta → 401 (sin token, pero pasó el filtro de versión)
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-App-Version: 1.0.0" \
  http://localhost:8000/api/v1/mobile/api/v1/data
# → 401
```

La versión mínima se controla desde la variable de entorno `MIN_APP_VERSION` (default `1.0.0`) en los tres servicios backend y desde el plugin Lua de Kong en `kong.yml`. Para actualizar la versión permitida, modifica ambos.

#### 4.3 Autenticación biométrica (Android)

La biometría usa `@aparajita/capacitor-biometric-auth` y guarda el refresh token con `@capacitor/preferences`. Solo funciona en dispositivo o emulador Android con huella / PIN configurado.

**Prerequisitos:**

```bash
cd ionic-app/poc-security
npm install   # instala @aparajita/capacitor-biometric-auth y @capacitor/preferences
npx cap sync android
```

Verificar que `android/app/src/main/AndroidManifest.xml` tenga el permiso:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

**Flujo en la app:**

1. Primer login con usuario/contraseña en Tab "Identidad" → el refresh token se guarda automáticamente.
2. En el siguiente arranque de la app (dispositivo con biometría disponible) → aparece el botón "Entrar con biometría".
3. Al pulsar → se lanza el prompt biométrico del sistema → si se confirma, se usa el refresh token para renovar la sesión.
4. Al cerrar sesión o si el refresh token expira → la opción desaparece hasta el próximo login con contraseña.

> El refresh token se almacena en `@capacitor/preferences` (SharedPreferences en Android). Para producción, reemplazar con `EncryptedSharedPreferences` (Android Keystore).

#### 4.4 Passkeys — login sin contraseña (Web)

Las passkeys usan el flujo WebAuthn Passwordless de Keycloak con PKCE Authorization Code. Solo funciona en el canal web (`http://localhost:4200`), en Chrome/Safari/Edge con soporte WebAuthn.

**Paso 1 — Registrar una passkey para el usuario**

Las passkeys se registran desde la cuenta de Keycloak del usuario. Con el stack levantado:

```
http://localhost:8080/realms/web-realm/account
```

1. Inicia sesión con `testuser / Test1234!`
2. Ve a **Security → Passwordless** (o **Signing in → Passkeys**)
3. Haz clic en **Set up security key** y sigue el prompt del navegador/SO

**Paso 2 — Usar la passkey desde la app**

1. Abre `http://localhost:4200`
2. En Tab "Identidad", debajo del formulario de contraseña, aparece el botón **"Iniciar sesión con Passkey"**
3. Al pulsar se redirige a Keycloak con `acr_values=webauthn-passwordless`
4. Keycloak muestra el prompt WebAuthn → confirma con huella/PIN del SO
5. Keycloak redirige a `http://localhost:4200/auth/callback?code=...`
6. La app intercambia el código por tokens (PKCE) y queda autenticada

**Verificar el flujo:**

```bash
# El callback route debe estar registrado en Keycloak (realm-web.json lo incluye)
curl -s "http://localhost:8080/admin/realms/web-realm/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "
import sys,json
clients = json.load(sys.stdin)
web = next(c for c in clients if c['clientId']=='web-app-client')
print('redirectUris:', web['redirectUris'])
"
# Debe incluir: http://localhost:4200/auth/callback
```

> En producción el `rpId` de WebAuthn debe coincidir exactamente con el dominio (no `localhost`). Ver `webAuthnPolicyPasswordlessRpId` en `keycloak-config/realm-web.json`.

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
   - Botón "Cambiar contraseña" → formulario inline con validaciones en tiempo real; el backend verifica la contraseña actual via re-auth Keycloak antes de aplicar el cambio

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

Al finalizar se genera automáticamente un reporte HTML en `docs/test-reports/test-all-YYYYMMDD-HHMMSS.html` con el detalle de cada test, código de color por sección y resumen de resultados.

**Resultado esperado: 98/98 PASS**

17 secciones — 10 de integración + 6 pentest/resiliencia + 1 disaster recovery:

| Sección | Qué cubre |
|---------|-----------|
| 1/17 · Infraestructura | 7 contenedores corriendo y saludables |
| 2/17 · Keycloak | OIDC discovery, tokens, audience claims por realm |
| 3/17 · Clave RSA | Simulación WebCrypto: generación, exportación, binding |
| 4/17 · Kong | Security headers, correlation ID, routing por canal |
| 5/17 · Servicios | 6 flujos JWE (3 servicios × 2 canales) |
| 6/17 · Seguridad | Rechazos cross-channel, sin token, firma inválida |
| 7/17 · Endpoints POST | Creación de transferencias y pagos por canal |
| 8/17 · Brute Force | Bloqueo de cuenta tras intentos fallidos, reset via admin API |
| 9/17 · Version Enforcement | HTTP 426 en cada ruta con versión incorrecta o ausente |
| 10/17 · Aislamiento por servicio | Rol insuficiente, audiencias cruzadas entre servicios |
| 11/17 · JWT Algorithm Attacks | alg=none, RS256→HS256, kid/jku externo, claims elevados |
| 12/17 · Injection Attacks | SQL, XSS, path traversal en headers y rutas |
| 13/17 · Information Disclosure | Fingerprinting, enumeración de usuarios, error leakage |
| 14/17 · Security Headers & CORS | CSP, HSTS, X-Frame-Options, CORS policy |
| 15/17 · Rate Limiting & Payload Abuse | Burst 35 req (límite 30), payload 1 MB, null byte |
| 16/17 · Emergency Lockdown | Activación O(1), bloqueo pre-lockdown, tokens post-lockdown válidos, lift |
| 17/17 · Disaster Recovery | Redis fail-open, circuit breaker Odoo, killswitch Kong ON/OFF |

### Suite de seguridad Android (APK + emulador)

Analiza el APK estáticamente (ProGuard, Manifest flags, URLs hardcodeadas) y en runtime contra un emulador local (ADB backup, FLAG_SECURE, Frida detection, WebView debug, clipboard).

**Prerequisitos:**
- Android Studio instalado con al menos un emulador (API 34 recomendado) corriendo.
- En Windows: `$env:LOCALAPPDATA\Android\Sdk` y JBR en la ruta por defecto de Android Studio.
- En macOS M1/M2/M3/M4: `~/Library/Android/sdk` y Android Studio en `/Applications`.

```powershell
# Windows (PowerShell)
.\ionic-app\poc-security\scripts\test-android-security.ps1

# macOS (PowerShell 7 o superior requerido)
pwsh ionic-app/poc-security/scripts/test-android-security.ps1
```

El script detecta el sistema operativo automáticamente — usa los paths correctos de SDK, JBR y comandos para cada plataforma.

**Resultado esperado (emulador de desarrollo):**

| Resultado | Tests | Detalle |
|-----------|-------|---------|
| PASS | 11 | Detección de dispositivo, install APK, launch app, ProGuard, Manifest flags, ADB backup bloqueado, clipboard limpio, URLs, network_security_config, JS bundle |
| FAIL (esperado) | 4 | FLAG_SECURE (limitación del emulador), Log stripping (logcat demasiado verboso), Frida detection (no implementado), WebView debug (habilitado en dev build) |
| SKIP | 2 | Tests que dependen de runtime previo fallido |

> Los FAILs son hallazgos reales documentados — no bugs del script. En un build de producción se corregirían deshabilitando WebView debug y añadiendo detección de Frida en `MainActivity.java`.

Los screenshots y logs de cada fase se guardan en `docs/android-test-reports/`.

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

### Utilidad: cifrado JWE manual (`encrypt-body.js`)

Cifra un payload JSON como JWE compacto (RSA-OAEP-256 + A256GCM) para probar manualmente los endpoints POST del canal mobile que requieren `Content-Type: application/jose`.

```bash
# 1. Obtener la clave pública del servidor
PUB=$(curl -s http://localhost:8000/api/v1/pubkey | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['jwk'])" | python3 -c "import sys,json,base64; print(base64.b64encode(sys.stdin.read().encode()).decode())")

# 2. Cifrar un payload
JWE=$(node scripts/encrypt-body.js "$(echo $PUB | base64 -d)" '{"amount":100,"to":"ACC-1234","memo":"test"}')

# 3. Enviar como body cifrado
curl -X POST http://localhost:8000/api/v1/mobile/transfers \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/jose" \
  -H "X-App-Version: 1.0.0" \
  -d "$JWE"
```

> El canal mobile rechaza con HTTP 415 si el body **no** está cifrado. El canal web acepta JSON plano.

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
| `POST /api/v1/web/change-password` | api-node | web | 60/min |
| `POST /api/v1/mobile/change-password` | api-node | mobile | 30/min |

**Headers requeridos en todas las peticiones:**
```
Authorization: Bearer <JWT>
X-Client-Public-Key: <base64( JSON(JWK) )>   ← clave pública RSA como objeto JWK serializado en JSON y luego base64
```

**Formato de respuesta:** `Content-Type: application/jose; charset=utf-8` (JWE compact — 5 partes separadas por `.`)

**Headers de respuesta reales (observados en vivo):**
```
Content-Type: application/jose; charset=utf-8
Cache-Control: no-store
X-Request-Id: <uuid>              ← correlation ID (echo del plugin Kong correlation-id)
X-Kong-Request-Id: <hex>          ← ID interno de Kong (diferente al anterior)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=()
Via: kong/3.5.0
```
> `X-Powered-By` y `ETag` ausentes — desactivados en los 3 servicios (control P4 implementado).

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
│           │   ├── auth.service.ts      # Login Keycloak + JWT expiry + changePassword()
│           │   ├── api.service.ts       # Llamadas JWE a los servicios
│           │   ├── crypto.service.ts    # WebCrypto RSA-OAEP + compactDecrypt
│           │   └── platform.service.ts  # Detección web vs Capacitor
│           ├── tab1/     # Login + Identity + Timer de sesión + Cambio de contraseña
│           ├── tab2/     # Transferencias
│           └── tab3/     # Pagos
│       └── scripts/
│           └── test-android-security.ps1  # Suite de seguridad Android (Windows + macOS M4)
├── odoo-custom-addons/
│   └── api_security_poc/  # Addon Odoo: x_api_clientes + HTTP controller
├── keycloak-config/       # realm-mobile.json + realm-web.json (auto-import)
├── shared-keys/           # Certificados TLS + claves RSA (generados, no en repo)
├── docker/
│   ├── android-test-runner/  # Runner Docker para CI: conecta ADB remoto + ejecuta suite
│   └── db-init/              # Scripts SQL de inicialización de PostgreSQL
├── scripts/
│   ├── setup.sh           # Script de configuración inicial
│   ├── test-all.sh        # Suite de integración (98 tests) → genera HTML en docs/test-reports/
│   └── killswitch.sh      # Bloqueo de emergencia vía Kong
├── docs/
│   ├── index.html         # Presentación ejecutiva (slides animados)
│   ├── arch.html          # Architecture Review
│   ├── request-flow.html  # Flujo paso a paso PKCE → JWE
│   ├── stride.html        # Modelo de amenazas STRIDE
│   ├── attack-repudiation.html  # Ataques repudiados y controles
│   ├── test-reports/      # Reportes HTML generados por test-all.sh (gitignored)
│   └── android-test-reports/   # Logs y screenshots de test-android-security.ps1
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

**Implementado en el POC:**

| Control | Estado |
|---------|--------|
| `/internal/validate-user` | ✅ Protegido con `validateJWT` + `X-Internal-Secret` |
| `X-Powered-By: Express` | ✅ Desactivado en los 3 servicios |
| ETag en respuestas JWE | ✅ Desactivado en los 3 servicios |
| Odoo AuthZ | ✅ Activo en api-node + transfers + payments |
| Circuit Breaker | ✅ `opossum` en los 3 servicios — OPEN state → 503 + `Retry-After: 30` |
| Revocación de tokens (JTI) | ✅ Redis blacklist por JTI con TTL = vida restante del token |
| Emergency Lockdown | ✅ `SET emergency:lockdown <epoch>` → invalida todos los tokens en O(1); `DELETE` para levantar |
| Stores distribuidos (Redis) | ✅ pubkey binding, idempotency, blacklist, lockdown — Redis 7 en docker-compose |
| `app_version` JWT claim | ✅ Keycloak hardcoded mapper — versión server-side en JWT, no forgeable por el cliente |
| Biometric auth (mobile) | ✅ `@aparajita/capacitor-biometric-auth` + refresh token en `@capacitor/preferences` |
| Passkeys / WebAuthn | ✅ Keycloak WebAuthn Passwordless + PKCE Auth Code flow en Ionic |

**Antes de producción — Prioridad alta:**

| Item | POC | Producción |
|------|-----|------------|
| Consolidación de realms | `web-realm` + `mobile-realm` separados — cambio de contraseña no se propaga | Realm único `app-realm`; canales separados por cliente (`web-app-client` / `mobile-app-client`) |
| Credenciales DB | Hardcodeadas en docker-compose | Docker Secrets / Vault con AppRole + TTL corto |
| Keycloak admin | `admin/admin` | Contraseña fuerte + MFA + acceso solo desde red interna |
| Keycloak admin-cli | Credenciales en env vars de `api-node` | `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASS` en Vault con AppRole + TTL corto |
| Llaves RSA | Archivos PEM planos en `/shared-keys` | HSM o AWS KMS — nunca material de clave en disco |
| Play Integrity / App Attest | `app_version` claim hardcodeado en Keycloak | Play Integrity API (Android) + App Attest (iOS) — atestación de integridad del binario |

**Antes de producción — Prioridad media:**

| Item | POC | Producción |
|------|-----|------------|
| `secure-net` | `internal: false` | `internal: true` — servicios backend no accesibles desde exterior |
| Certificados | Autofirmados | Let's Encrypt / CA corporativa |
| SSL Pinning | Sin pin real (cert autofirmado) | SHA-256 del cert de producción en `network_security_config.xml` |
| Rate limiting | Policy local (un nodo) | Redis backend (multi-nodo, comparte contadores entre instancias) |
| Logging | Console stdout | ELK / Loki estructurado con correlation ID |
| Segregar rutas web/mobile | Mismos endpoints para ambos canales | Rutas, audiencias y permisos separados en Kong |
| Monitorización | Logs locales sin alertas | SIEM con alertas en rechazos de seguridad (rate limit, 401, 403, lockdown activado) |
| Almacenamiento refresh token | `@capacitor/preferences` (SharedPreferences plano) | `EncryptedSharedPreferences` (Android Keystore) |

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

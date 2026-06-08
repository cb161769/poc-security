# POC Seguridad API — Microservicios con JWT + JWE

Prueba de concepto de arquitectura de seguridad para APIs móviles y web.  
Implementa autenticación federada, cifrado de payload de extremo a extremo y autorización de negocio.

### Animaciones interactivas

| Animación | Descripción |
|-----------|-------------|
| [docs/request-flow.html](docs/request-flow.html) | Flujo paso a paso: PKCE → JWT → RSA keygen → Kong → JWKS → Odoo AuthZ → JWE encrypt → decrypt (11 pasos animados) |
| [docs/stride.html](docs/stride.html) | Modelo de amenazas STRIDE: vectores de ataque y contramedidas implementadas por categoría |

> Abre los archivos directamente en el navegador — no requieren servidor.

---

## Arquitectura

```
App Ionic (Web / Mobile)
  │
  ├── Keycloak 26 ──── Autenticación PKCE + JWT RS256
  │     ├── web-realm   (aud: web-api   · TTL: 5 min)
  │     └── mobile-realm (aud: mobile-api · TTL: 15 min)
  │
  └── Kong 3.5 ──────── Perímetro TLS + Rate Limiting
        ├── /api/v1/web/**    → 60 req/min · X-Channel: web
        └── /api/v1/mobile/** → 30 req/min · X-Channel: mobile
              │
              ├── api-node:3000       Identity Bridge + Odoo AuthZ
              ├── transfers-service:3001  Servicio de Transferencias
              └── payments-service:3002   Servicio de Pagos
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

## Ejecutar las pruebas

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
X-Client-Public-Key: <RSA-JWK-base64>
```

**Formato de respuesta:** `Content-Type: application/jose` (JWE compact — 5 partes separadas por `.`)

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
| `/internal/validate-user` | Sin auth | Requiere `X-Internal-Secret` |
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

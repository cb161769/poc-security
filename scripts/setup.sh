#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  setup.sh — POC Security · Configuración inicial completa
#  Ejecutar UNA SOLA VEZ en una máquina nueva.
# ═══════════════════════════════════════════════════════════
set -uo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${B}▶ $1${NC}"; }
success() { echo -e "${G}✅ $1${NC}"; }
warn()    { echo -e "${Y}⚠️  $1${NC}"; }
die()     { echo -e "${R}❌ $1${NC}"; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── 1. Prerequisitos ─────────────────────────────────────
info "Verificando prerequisitos..."
command -v docker  >/dev/null 2>&1 || die "Docker no encontrado. Instala Docker Desktop."
command -v openssl >/dev/null 2>&1 || die "OpenSSL no encontrado."
command -v curl    >/dev/null 2>&1 || die "curl no encontrado."
command -v python3  >/dev/null 2>&1 || die "Python no encontrado."
command -v node    >/dev/null 2>&1 || die "Node.js no encontrado."
docker info >/dev/null 2>&1        || die "Docker no está corriendo. Inicia Docker Desktop."
success "Prerequisitos OK"

# ── 2. Generar certificados TLS y PKI ────────────────────
info "Generando certificados en shared-keys/..."
mkdir -p shared-keys

# CA autofirmada
openssl genrsa -out shared-keys/ca.key 4096 2>/dev/null
openssl req -new -x509 -days 825 -key shared-keys/ca.key \
  -subj "/C=DO/O=InternalCA/OU=Security/CN=internal-ca" \
  -out shared-keys/ca.pem 2>/dev/null

# Clave del servidor Kong
openssl genrsa -out shared-keys/kong.key 4096 2>/dev/null

# CSR + cert firmado por la CA
openssl req -new -key shared-keys/kong.key \
  -subj "/C=DO/O=API/OU=Gateway/CN=localhost" \
  -out /tmp/kong.csr 2>/dev/null
openssl x509 -req -in /tmp/kong.csr -CA shared-keys/ca.pem \
  -CAkey shared-keys/ca.key -CAcreateserial \
  -days 825 -out shared-keys/fullchain.pem 2>/dev/null
rm -f /tmp/kong.csr

# Par RSA para cifrado JWE (key-rotator lo renueva cada 24h)
openssl genrsa -out shared-keys/priv.pem 2048 2>/dev/null
openssl rsa -in shared-keys/priv.pem -pubout -out shared-keys/pub.pem 2>/dev/null
date > shared-keys/last_rotation.txt

success "Certificados generados"

# ── 3. Crear directorio certs para certbot ───────────────
mkdir -p certs

# ── 5. Levantar Docker Compose ───────────────────────────
info "Levantando stack con Docker Compose..."
docker compose up -d --build
success "Contenedores iniciados"

# ── 6. Esperar a que los servicios estén listos ──────────
info "Esperando a Keycloak (puede tomar 60–90s)..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:8080/realms/master" >/dev/null 2>&1; then
    success "Keycloak listo"
    break
  fi
  echo -n "."
  sleep 5
done
curl -sf "http://localhost:8080/realms/master" >/dev/null 2>&1 || die "Keycloak no respondió"

info "Esperando a Odoo..."
for i in $(seq 1 20); do
  if curl -sf "http://localhost:8069" >/dev/null 2>&1; then
    success "Odoo listo"
    break
  fi
  echo -n "."
  sleep 5
done

# ── 7. Configurar Keycloak ───────────────────────────────
info "Configurando Keycloak (reinos, clientes, usuarios)..."

ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

[[ -z "$ADMIN_TOKEN" ]] && die "No se pudo obtener token de admin de Keycloak"

# Crear web-realm (puede fallar si ya existe — se ignora)
curl -s -X POST "http://localhost:8080/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @keycloak-config/realm-web.json >/dev/null 2>&1 || true
success "web-realm configurado"

# Función para crear usuario
create_user() {
  local REALM=$1 CLIENT_ID=$2 CLIENT_SECRET=$3 ROLE=$4

  ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  # Crear usuario
  curl -s -X POST "http://localhost:8080/admin/realms/$REALM/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "{\"username\":\"testuser\",\"email\":\"testuser@poc.com\",\"firstName\":\"Test\",\"lastName\":\"User\",\"emailVerified\":true,\"enabled\":true,\"requiredActions\":[],\"credentials\":[{\"type\":\"password\",\"value\":\"Test1234!\",\"temporary\":false}]}" \
    >/dev/null 2>&1 || true

  # Audience mapper
  CID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://localhost:8080/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)

  [[ -n "$CID" ]] && curl -s -X POST \
    "http://localhost:8080/admin/realms/$REALM/clients/$CID/protocol-mappers/models" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\":\"${ROLE}-audience\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-audience-mapper\",\"config\":{\"included.custom.audience\":\"${ROLE}\",\"access.token.claim\":\"true\",\"id.token.claim\":\"false\"}}" \
    >/dev/null 2>&1 || true

  # Asignar rol
  USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://localhost:8080/admin/realms/$REALM/users?username=testuser" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)

  ROLE_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://localhost:8080/admin/realms/$REALM/roles/$ROLE" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null)

  [[ -n "$USER_ID" && -n "$ROLE_ID" ]] && curl -s -X POST \
    "http://localhost:8080/admin/realms/$REALM/users/$USER_ID/role-mappings/realm" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "[{\"id\":\"$ROLE_ID\",\"name\":\"$ROLE\"}]" >/dev/null 2>&1 || true
}

create_user "mobile-realm" "mobile-app-client" "" "user-api"
success "testuser creado en mobile-realm"

create_user "web-realm" "web-app-client" "" "user-web"
success "testuser creado en web-realm"

# ── 8. Inicializar Odoo ──────────────────────────────────
info "Inicializando base de datos Odoo (tarda ~2 min)..."
docker exec odoo-server sh -c \
  "odoo --stop-after-init -d pocdb --init=api_security_poc \
   --db_host=db-poc --db_port=5432 \
   --db_user=admin_seguro --db_password=password_2026 2>&1" \
  | tail -3

# Reiniciar Odoo para usar pocdb
docker compose restart odoo
sleep 8

# Crear registro en x_api_clientes para ambos usuarios
info "Creando registros de autorización en Odoo..."
docker exec odoo-server sh -c "
curl -s -c /tmp/c.txt -X POST 'http://localhost:8069/web/session/authenticate' \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":{\"db\":\"pocdb\",\"login\":\"admin\",\"password\":\"admin\"}}' > /dev/null

WEB_SUB=\$(curl -s -X POST 'http://localhost:8080/realms/web-realm/protocol/openid-connect/token' \
  -d 'client_id=web-app-client&username=testuser&password=Test1234!&grant_type=password' \
  | python3 -c 'import sys,json,base64; t=json.load(sys.stdin)[\"access_token\"].split(\".\")[1]; t+=\"==\"*(4-len(t)%4); print(json.loads(base64.b64decode(t))[\"sub\"])' 2>/dev/null || echo '')

MOB_SUB=\$(curl -s -X POST 'http://localhost:8080/realms/mobile-realm/protocol/openid-connect/token' \
  -d 'client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password' \
  | python3 -c 'import sys,json,base64; t=json.load(sys.stdin)[\"access_token\"].split(\".\")[1]; t+=\"==\"*(4-len(t)%4); print(json.loads(base64.b64decode(t))[\"sub\"])' 2>/dev/null || echo '')

curl -s -b /tmp/c.txt -X POST 'http://localhost:8069/web/dataset/call_kw' \
  -H 'Content-Type: application/json' \
  -d \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"method\\\":\\\"call\\\",\\\"params\\\":{\\\"model\\\":\\\"x_api_clientes\\\",\\\"method\\\":\\\"create\\\",\\\"args\\\":[{\\\"name\\\":\\\"Test User Web\\\",\\\"sub\\\":\\\"\$WEB_SUB\\\",\\\"email\\\":\\\"testuser@poc.com\\\",\\\"client_id\\\":\\\"web-app-client\\\",\\\"active\\\":true}],\\\"kwargs\\\":{}}}\" > /dev/null 2>&1 || true

curl -s -b /tmp/c.txt -X POST 'http://localhost:8069/web/dataset/call_kw' \
  -H 'Content-Type: application/json' \
  -d \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"method\\\":\\\"call\\\",\\\"params\\\":{\\\"model\\\":\\\"x_api_clientes\\\",\\\"method\\\":\\\"create\\\",\\\"args\\\":[{\\\"name\\\":\\\"Test User Mobile\\\",\\\"sub\\\":\\\"\$MOB_SUB\\\",\\\"email\\\":\\\"testuser@poc.com\\\",\\\"client_id\\\":\\\"mobile-app-client\\\",\\\"active\\\":true}],\\\"kwargs\\\":{}}}\" > /dev/null 2>&1 || true
" 2>/dev/null
success "Registros Odoo creados"

# ── 9. Instalar dependencias raíz (Playwright + encrypt-body) ────────────────
info "Instalando dependencias raíz..."
cd "$ROOT"
npm install --silent
success "npm install raíz completado"

# ── 10. Instalar dependencias de la Ionic App y sincronizar Capacitor ────────
info "Instalando dependencias de la Ionic App..."
cd "$ROOT/ionic-app/poc-security"
npm install --silent
success "npm install Ionic completado"

info "Sincronizando Capacitor con Android (biometría + plugins)..."
npx cap sync android --silent 2>/dev/null || warn "cap sync falló — Android Studio o SDK no encontrado (opcional para pruebas web)"

# ── RESUMEN ──────────────────────────────────────────────
echo ""
echo -e "${G}═══════════════════════════════════════════════════${NC}"
echo -e "${G}  🎉 Setup completado${NC}"
echo -e "${G}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${B}Servicios:${NC}"
echo -e "    Kong      → http://localhost:8000"
echo -e "    Keycloak  → http://localhost:8080"
echo -e "    Odoo      → http://localhost:8069"
echo ""
echo -e "  ${B}Para iniciar la app Ionic:${NC}"
echo -e "    cd ionic-app/poc-security && npm start"
echo -e "    Luego abre: http://localhost:4200"
echo ""
echo -e "  ${B}Credenciales de prueba:${NC}"
echo -e "    Usuario: testuser"
echo -e "    Contraseña: Test1234!"
echo ""
echo -e "  ${B}Para ejecutar las pruebas:${NC}"
echo -e "    bash scripts/test-all.sh"
echo ""
echo -e "  ${B}Tests Android (requiere Android Studio + emulador):${NC}"
echo -e "    pwsh ionic-app/poc-security/scripts/test-android-security.ps1"
echo ""

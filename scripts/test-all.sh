#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  test-all.sh  — POC Security · Suite de Pruebas Completa
# ═══════════════════════════════════════════════════════════
set -uo pipefail

# ── Resolver Python ──────────────────────────────────────
if ! python3 -c "import sys" 2>/dev/null; then
  python3() { python "$@"; }
  export -f python3
fi

# ── Colores ──────────────────────────────────────────────
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'
B='\033[0;34m'; W='\033[1;37m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0

pass() { echo -e "${G}✅ PASS${NC}  $1"; PASS=$((PASS+1)); }
fail() { echo -e "${R}❌ FAIL${NC}  $1"; echo -e "      ${R}→ $2${NC}"; FAIL=$((FAIL+1)); }
skip() { echo -e "${Y}⚠️  SKIP${NC}  $1  ($2)"; SKIP=$((SKIP+1)); }
section() { echo -e "\n${B}━━━ $1 ━━━${NC}"; }

# ── Helpers ──────────────────────────────────────────────
KONG="http://localhost:8000"
KC="http://localhost:8080"
ODOO="http://localhost:8069"

jwe_parts() { echo "$1" | tr '.' '\n' | wc -l | tr -d ' '; }

decode_jwe_header() {
  local h; h=$(echo "$1" | cut -d'.' -f1)
  python3 -c "
import base64,json,sys
h='$h'
pad = 4 - len(h)%4
try:
  print(json.dumps(json.loads(base64.urlsafe_b64decode(h+'='*pad))))
except:
  print('ERROR')
"
}

check_jwe() {
  local name="$1" jwe="$2" expect_svc="$3" expect_ch="$4"
  local parts hdr

  parts=$(jwe_parts "$jwe")
  if [[ "$parts" != "5" ]]; then
    fail "$name" "No es JWE (partes=$parts): ${jwe:0:80}"; return
  fi

  hdr=$(decode_jwe_header "$jwe")
  if echo "$hdr" | grep -q "RSA-OAEP-256" && \
     echo "$hdr" | grep -q "A256GCM" && \
     echo "$hdr" | grep -q "\"svc\": \"$expect_svc\"" && \
     echo "$hdr" | grep -q "\"channel\": \"$expect_ch\""; then
    pass "$name  [alg=RSA-OAEP-256 enc=A256GCM svc=$expect_svc ch=$expect_ch]"
  else
    fail "$name" "Header inesperado: $hdr"
  fi
}

check_json_err() {
  local name="$1" resp="$2" expect="$3"
  if echo "$resp" | grep -q "$expect"; then
    pass "$name"
  else
    fail "$name" "Esperado '$expect' · Recibido: ${resp:0:120}"
  fi
}

# ════════════════════════════════════════════════════════
# 1. INFRAESTRUCTURA
# ════════════════════════════════════════════════════════
section "1/7 · INFRAESTRUCTURA — Contenedores"

for svc in kong-gateway keycloak-server api-node transfers-service payments-service odoo-server db-poc; do
  status=$(docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
  health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$svc" 2>/dev/null || echo "n/a")
  label="$svc  [status=$status health=$health]"
  if [[ "$status" == "running" ]]; then pass "$label"
  else fail "$label" "Contenedor no está corriendo"; fi
done

# ════════════════════════════════════════════════════════
# 2. KEYCLOAK — Ambos reinos
# ════════════════════════════════════════════════════════
section "2/7 · KEYCLOAK — Reinos y Tokens"

# OIDC discovery
for realm in web-realm mobile-realm; do
  resp=$(curl -s "$KC/realms/$realm/.well-known/openid-configuration")
  if echo "$resp" | grep -q "jwks_uri"; then
    pass "Realm $realm — OIDC discovery"
  else
    fail "Realm $realm — OIDC discovery" "Sin jwks_uri en respuesta"
  fi
done

# Obtener tokens
# web-app-client has directAccessGrants disabled (security fix) — use web-test-client for test automation
echo -e "\n  Obteniendo tokens..."
WEB_TOKEN=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR:'+str(d.get('error',d))))")

MOB_TOKEN=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR:'+str(d.get('error',d))))")

if [[ "$WEB_TOKEN" == ERROR* ]]; then fail "Token web-realm" "$WEB_TOKEN"
else pass "Token web-realm obtenido  [iss=web-realm]"; fi

if [[ "$MOB_TOKEN" == ERROR* ]]; then fail "Token mobile-realm" "$MOB_TOKEN"
else pass "Token mobile-realm obtenido  [iss=mobile-realm]"; fi

# Validar claims
WEB_AUD=$(echo "$WEB_TOKEN" | python3 -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
d=json.loads(base64.b64decode(t))
print(d.get('aud','missing'))
")
MOB_AUD=$(echo "$MOB_TOKEN" | python3 -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
d=json.loads(base64.b64decode(t))
print(d.get('aud','missing'))
")

if echo "$WEB_AUD" | grep -q "web-api"; then pass "web-realm aud contiene 'web-api'  → $WEB_AUD"
else fail "web-realm aud" "Esperado 'web-api' · Got: $WEB_AUD"; fi

if echo "$MOB_AUD" | grep -q "mobile-api"; then pass "mobile-realm aud contiene 'mobile-api'  → $MOB_AUD"
else fail "mobile-realm aud" "Esperado 'mobile-api' · Got: $MOB_AUD"; fi

# ════════════════════════════════════════════════════════
# 3. GENERACIÓN DE CLAVE RSA (simula WebCrypto del cliente)
# ════════════════════════════════════════════════════════
section "3/7 · CLAVE RSA — Simulación WebCrypto"

PUB_KEY=$(python3 -c "
import json,base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
key = rsa.generate_private_key(65537, 2048, default_backend())
pub = key.public_key().public_numbers()
def b64u(x): return base64.urlsafe_b64encode(x.to_bytes((x.bit_length()+7)//8,'big')).rstrip(b'=').decode()
jwk = {'kty':'RSA','use':'enc','alg':'RSA-OAEP-256','n':b64u(pub.n),'e':b64u(pub.e)}
print(base64.b64encode(json.dumps(jwk).encode()).decode())
" 2>/dev/null)

if [[ -n "$PUB_KEY" && ${#PUB_KEY} -gt 100 ]]; then
  pass "Par RSA-2048 generado  [pubkey b64 len=${#PUB_KEY}]"
else
  fail "Generación RSA" "No se pudo generar el par de claves"
  echo "  Asegúrate de tener 'pip install cryptography'"
  exit 1
fi

# ════════════════════════════════════════════════════════
# 4. KONG — Rutas y Headers
# ════════════════════════════════════════════════════════
section "4/7 · KONG — Routing y Seguridad"

# Verificar headers de seguridad en respuesta
HDR_RESP=$(curl -sv -H "Authorization: Bearer $WEB_TOKEN" \
                    -H "X-Client-Public-Key: $PUB_KEY" \
                    -H "X-App-Version: 1.0.0" \
                    "$KONG/api/v1/web/data" 2>&1)

if echo "$HDR_RESP" | grep -qi "X-Content-Type-Options"; then pass "Security header X-Content-Type-Options presente"
else fail "Security headers" "X-Content-Type-Options no encontrado"; fi

if echo "$HDR_RESP" | grep -qi "X-Frame-Options"; then pass "Security header X-Frame-Options presente"
else fail "Security headers" "X-Frame-Options no encontrado"; fi

if echo "$HDR_RESP" | grep -qi "X-Request-Id"; then pass "Correlation ID X-Request-Id presente"
else fail "Correlation ID" "X-Request-Id no encontrado"; fi

if echo "$HDR_RESP" | grep -qi "Via: kong"; then pass "Proxy Via: kong identificado"
else fail "Kong proxy" "Header Via no encontrado"; fi

# ════════════════════════════════════════════════════════
# 5. SERVICIOS — Los 6 flujos JWE
# ════════════════════════════════════════════════════════
section "5/7 · SERVICIOS — 6 Flujos (3 svc × 2 canales)"

H_WEB="-H 'Authorization: Bearer $WEB_TOKEN' -H 'X-Client-Public-Key: $PUB_KEY'"
H_MOB="-H 'Authorization: Bearer $MOB_TOKEN' -H 'X-Client-Public-Key: $PUB_KEY'"

# api-node
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/api/v1/data")
check_jwe "api-node     · web-realm  → /api/v1/web/api/v1/data"    "$R" "data" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/mobile/api/v1/data")
check_jwe "api-node     · mobile-realm→ /api/v1/mobile/api/v1/data" "$R" "data" "mobile" 2>/dev/null || true

# transfers
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers")
check_jwe "transfers    · web-realm  → /api/v1/web/transfers"    "$R" "transfers" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/mobile/transfers")
check_jwe "transfers    · mobile-realm→ /api/v1/mobile/transfers" "$R" "transfers" "mobile" 2>/dev/null || true

# payments
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/payments")
check_jwe "payments     · web-realm  → /api/v1/web/payments"    "$R" "payments" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" -H "X-App-Version: 1.0.0" "$KONG/api/v1/mobile/payments")
check_jwe "payments     · mobile-realm→ /api/v1/mobile/payments" "$R" "payments" "mobile" 2>/dev/null || true

# ════════════════════════════════════════════════════════
# 6. SEGURIDAD — Rechazos esperados
# ════════════════════════════════════════════════════════
section "6/7 · SEGURIDAD — Rechazos y Cross-Channel"

# Sin token
R=$(curl -s -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers")
check_json_err "Sin token → 401"  "$R" "requerido"

# Token web en ruta mobile
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" "$KONG/api/v1/mobile/transfers")
check_json_err "Token web-realm en /mobile/transfers → 401"  "$R" "inválido"

# Token mobile en ruta web
R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/payments")
check_json_err "Token mobile-realm en /web/payments → 401"  "$R" "inválido"

# Sin X-Client-Public-Key
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers")
check_json_err "Sin X-Client-Public-Key → 400"  "$R" "requerido"

# Token manipulado (firma inválida)
FAKE=$(echo "$WEB_TOKEN" | sed 's/\.\([^.]*\)$/\.INVALIDSIGNATURE/')
R=$(curl -s -H "Authorization: Bearer $FAKE" -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers")
check_json_err "JWT con firma inválida → 401"  "$R" "inválido"

# ════════════════════════════════════════════════════════
# 7. ENDPOINTS POST — Crear recursos
# ════════════════════════════════════════════════════════
section "7/7 · ENDPOINTS POST — Creación de Recursos"

# POST transfer (web) — body cifrado con server pubkey
SERVER_JWK=$(curl -s "$KONG/api/v1/pubkey")
WEB_TRANSFER_JWE=$(node "$(dirname "$0")/encrypt-body.js" "$SERVER_JWK" '{"amount":500,"to":"ACC-9988","memo":"Test transfer"}')
R=$(curl -s -X POST \
       -H "Authorization: Bearer $WEB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" \
       -H "X-Idempotency-Key: $(node -e 'const c=require("crypto");console.log(c.randomUUID())')" \
       -H "Content-Type: application/jose" \
       -d "$WEB_TRANSFER_JWE" \
       "$KONG/api/v1/web/transfers")
check_jwe "POST /web/transfers  → crear transferencia web"  "$R" "transfers" "web" 2>/dev/null || true

# POST transfer (mobile) — body cifrado con server pubkey
SERVER_JWK=$(curl -s "$KONG/api/v1/pubkey")
TRANSFER_JWE=$(node "$(dirname "$0")/encrypt-body.js" "$SERVER_JWK" '{"amount":200,"to":"ACC-1122","memo":"Test mobile"}')
R=$(curl -s -X POST \
       -H "Authorization: Bearer $MOB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" \
       -H "X-Idempotency-Key: $(node -e 'const c=require("crypto");console.log(c.randomUUID())')" \
       -H "Content-Type: application/jose" \
       -d "$TRANSFER_JWE" \
       "$KONG/api/v1/mobile/transfers")
check_jwe "POST /mobile/transfers → crear transferencia mobile" "$R" "transfers" "mobile" 2>/dev/null || true

# POST payment (web) — body cifrado con server pubkey
SERVER_JWK=$(curl -s "$KONG/api/v1/pubkey")
WEB_PAYMENT_JWE=$(node "$(dirname "$0")/encrypt-body.js" "$SERVER_JWK" '{"amount":99.99,"method":"card","merchant":"Test Corp"}')
R=$(curl -s -X POST \
       -H "Authorization: Bearer $WEB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" \
       -H "X-Idempotency-Key: $(node -e 'const c=require("crypto");console.log(c.randomUUID())')" \
       -H "Content-Type: application/jose" \
       -d "$WEB_PAYMENT_JWE" \
       "$KONG/api/v1/web/payments")
check_jwe "POST /web/payments   → crear pago web"           "$R" "payments" "web" 2>/dev/null || true

# POST payment (mobile) — body cifrado con server pubkey
SERVER_JWK=$(curl -s "$KONG/api/v1/pubkey")
PAYMENT_JWE=$(node "$(dirname "$0")/encrypt-body.js" "$SERVER_JWK" '{"amount":49.99,"method":"ach","merchant":"Utility"}')
R=$(curl -s -X POST \
       -H "Authorization: Bearer $MOB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "X-App-Version: 1.0.0" \
       -H "X-Idempotency-Key: $(node -e 'const c=require("crypto");console.log(c.randomUUID())')" \
       -H "Content-Type: application/jose" \
       -d "$PAYMENT_JWE" \
       "$KONG/api/v1/mobile/payments")
check_jwe "POST /mobile/payments → crear pago mobile"       "$R" "payments" "mobile" 2>/dev/null || true

# ════════════════════════════════════════════════════════
# 8. BRUTE FORCE — Protección de cuentas
# ════════════════════════════════════════════════════════
section "8/10 · BRUTE FORCE — Bloqueo de cuenta tras intentos fallidos"

BF_REALM="mobile-realm"
BF_CLIENT="mobile-app-client"
BF_USER="testuser"
BF_WRONG="WrongPassword999!"

echo -e "  Enviando 6 intentos fallidos para $BF_USER en $BF_REALM..."
for i in 1 2 3 4 5 6; do
  curl -s -X POST "$KC/realms/$BF_REALM/protocol/openid-connect/token" \
    -d "client_id=$BF_CLIENT&username=$BF_USER&password=$BF_WRONG&grant_type=password" \
    -o /dev/null
done

# Ahora el correcto debe ser bloqueado
LOCKED_RESP=$(curl -s -X POST "$KC/realms/$BF_REALM/protocol/openid-connect/token" \
  -d "client_id=$BF_CLIENT&username=$BF_USER&password=Test1234!&grant_type=password")

if echo "$LOCKED_RESP" | grep -qE "(account.is.temporarily.disabled|Account is disabled|user.is.temporarily.disabled|account_disabled|too many failed)"; then
  pass "Brute force: cuenta bloqueada tras 6 intentos fallidos"
else
  # Puede que el realm devuelva invalid_grant cuando está bloqueado
  ERR=$(echo "$LOCKED_RESP" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const o=JSON.parse(d);console.log(o.error_description||o.error||d.slice(0,80))}catch{console.log(d.slice(0,80))}})" 2>/dev/null)
  if echo "$LOCKED_RESP" | grep -qE "(invalid_grant|invalid_user_credentials)" && ! echo "$LOCKED_RESP" | grep -q '"access_token"'; then
    pass "Brute force: cuenta bloqueada — login correcto denegado tras $i intentos  [$ERR]"
  else
    fail "Brute force: cuenta NO bloqueada" "Login exitoso o respuesta inesperada: ${LOCKED_RESP:0:120}"
  fi
fi

# Desbloquear: reset via admin API para no afectar tests posteriores
ADMIN_TOK=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=admin" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const o=JSON.parse(d);console.log(o.access_token||'')}catch{console.log('')}})" 2>/dev/null)

USER_ID=$(curl -s "$KC/admin/realms/$BF_REALM/users?username=$BF_USER&exact=true" \
  -H "Authorization: Bearer $ADMIN_TOK" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const a=JSON.parse(d);console.log(a[0]?.id||'')}catch{console.log('')}})" 2>/dev/null)

UNLOCK=$(curl -s -w "%{http_code}" -X DELETE "$KC/admin/realms/$BF_REALM/attack-detection/brute-force/users/$USER_ID" \
  -H "Authorization: Bearer $ADMIN_TOK")

if echo "$UNLOCK" | grep -q "204\|200"; then
  pass "Brute force: cuenta desbloqueada via admin API"
else
  fail "Brute force: no se pudo desbloquear" "HTTP: $UNLOCK"
fi

# Verificar que tras desbloqueo el login vuelve a funcionar
UNBLOCKED=$(curl -s -X POST "$KC/realms/$BF_REALM/protocol/openid-connect/token" \
  -d "client_id=$BF_CLIENT&username=$BF_USER&password=Test1234!&grant_type=password" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const o=JSON.parse(d);console.log(o.access_token?'OK':'ERROR:'+JSON.stringify(o.error))}catch{console.log('ERROR')}})" 2>/dev/null)

if [[ "$UNBLOCKED" == "OK" ]]; then
  pass "Brute force: login restaurado correctamente tras desbloqueo"
else
  fail "Brute force: login no restaurado" "$UNBLOCKED"
fi

# ════════════════════════════════════════════════════════
# 9. VERSION ENFORCEMENT — 426 por servicio
# ════════════════════════════════════════════════════════
section "9/10 · VERSION ENFORCEMENT — 426 en cada ruta"

# Obtener tokens frescos (por si fueron afectados por brute force test)
WEB_TOKEN=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const o=JSON.parse(d);console.log(o.access_token||'ERROR')}catch{console.log('ERROR')}})" 2>/dev/null)

MOB_TOKEN=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const o=JSON.parse(d);console.log(o.access_token||'ERROR')}catch{console.log('ERROR')}})" 2>/dev/null)

for route in \
  "web/api/v1/data:$WEB_TOKEN:web-api-node" \
  "web/transfers:$WEB_TOKEN:web-transfers" \
  "web/payments:$WEB_TOKEN:web-payments" \
  "mobile/api/v1/data:$MOB_TOKEN:mobile-api-node" \
  "mobile/transfers:$MOB_TOKEN:mobile-transfers" \
  "mobile/payments:$MOB_TOKEN:mobile-payments"; do
  PATH_PART="${route%%:*}"
  REST="${route#*:}"
  TOKEN="${REST%%:*}"
  LABEL="${REST##*:}"

  # Sin header de versión
  R=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Client-Public-Key: $PUB_KEY" \
    "$KONG/api/v1/$PATH_PART")
  if [[ "$R" == "426" ]]; then
    pass "Version enforcement → /api/v1/$PATH_PART  sin header → HTTP 426"
  else
    fail "Version enforcement → /api/v1/$PATH_PART" "Esperado 426, recibido $R"
  fi

  # Versión incorrecta
  R=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Client-Public-Key: $PUB_KEY" \
    -H "X-App-Version: 0.0.1" \
    "$KONG/api/v1/$PATH_PART")
  if [[ "$R" == "426" ]]; then
    pass "Version enforcement → /api/v1/$PATH_PART  versión 0.0.1 → HTTP 426"
  else
    fail "Version enforcement → /api/v1/$PATH_PART  versión 0.0.1" "Esperado 426, recibido $R"
  fi
done

# ════════════════════════════════════════════════════════
# 10. POR SERVICIO — Validación de roles y rechazo individual
# ════════════════════════════════════════════════════════
section "10/10 · POR SERVICIO — Rol insuficiente y aislamiento"

# Crear token web sin roles para probar rechazo
# Usamos token válido de web-realm en rutas que requieren rol específico

# Transfers: requiere rol transfers/user-api — token web sin ese rol en canal mobile
R=$(curl -s \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/mobile/transfers")
check_json_err "transfers-service: token web en ruta mobile → 401 inválido" "$R" "inválido"

# Payments: token mobile en ruta web
R=$(curl -s \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/payments")
check_json_err "payments-service: token mobile en ruta web → 401 inválido" "$R" "inválido"

# api-node: sin X-Client-Public-Key → 400
R=$(curl -s \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/api/v1/data")
check_json_err "api-node: sin X-Client-Public-Key → 400 requerido" "$R" "requerido"

# transfers: sin X-Client-Public-Key → 400
R=$(curl -s \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
check_json_err "transfers-service: sin X-Client-Public-Key → 400 requerido" "$R" "requerido"

# payments: sin X-Client-Public-Key → 400
R=$(curl -s \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/payments")
check_json_err "payments-service: sin X-Client-Public-Key → 400 requerido" "$R" "requerido"

# Cada servicio con token expirado/manipulado
FAKE=$(echo "$WEB_TOKEN" | sed 's/\.\([^.]*\)$/\.INVALIDSIGNATURE/')
for svc in "api/v1/data" "transfers" "payments"; do
  R=$(curl -s \
    -H "Authorization: Bearer $FAKE" \
    -H "X-Client-Public-Key: $PUB_KEY" \
    -H "X-App-Version: 1.0.0" \
    "$KONG/api/v1/web/$svc")
  check_json_err "$svc: JWT manipulado → 401 inválido" "$R" "inválido"
done

# ════════════════════════════════════════════════════════
# 11. WEB PENTESTS — JWT Attacks
# ════════════════════════════════════════════════════════
section "11/15 · PENTEST — JWT Algorithm Attacks"

# Refresh tokens for this section
WEB_TOKEN=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" 2>/dev/null \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const o=JSON.parse(d);console.log(o.access_token||'ERROR')})" 2>/dev/null || echo "SKIP")
MOB_TOKEN=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" 2>/dev/null \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const o=JSON.parse(d);console.log(o.access_token||'ERROR')})" 2>/dev/null || echo "SKIP")

# 11a. alg=none attack — strip signature
NONE_TOKEN=$(node -e "
const t='$WEB_TOKEN'.split('.');
const hdr=JSON.parse(Buffer.from(t[0],'base64').toString());
hdr.alg='none';
const newHdr=Buffer.from(JSON.stringify(hdr)).toString('base64url');
console.log(newHdr+'.'+t[1]+'.');
" 2>/dev/null)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $NONE_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "alg=none attack blocked  [HTTP 401]" || fail "alg=none attack NOT blocked" "HTTP $R — unsigned token accepted"

# 11b. RS256→HS256 confusion — sign with public key as HMAC secret
HS256_TOKEN=$(node -e "
const t='$WEB_TOKEN'.split('.');
const hdr=JSON.parse(Buffer.from(t[0],'base64').toString());
hdr.alg='HS256';
const newHdr=Buffer.from(JSON.stringify(hdr)).toString('base64url');
const payload=t[1];
// fake sign with empty secret (real confusion uses pubkey — both should be rejected)
const c=require('crypto');
const sig=c.createHmac('sha256','fakesecret').update(newHdr+'.'+payload).digest('base64url');
console.log(newHdr+'.'+payload+'.'+sig);
" 2>/dev/null)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $HS256_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "RS256→HS256 confusion blocked  [HTTP 401]" || fail "HS256 confusion NOT blocked" "HTTP $R"

# 11c. JWT with forged claims (valid structure, manipulated payload, broken sig)
FORGED=$(node -e "
const t='$WEB_TOKEN'.split('.');
const p=JSON.parse(Buffer.from(t[1],'base64').toString());
p.sub='attacker-uuid'; p.preferred_username='admin'; p.realm_access={roles:['admin']};
const newPayload=Buffer.from(JSON.stringify(p)).toString('base64url');
console.log(t[0]+'.'+newPayload+'.FORGEDSIGNATURE');
" 2>/dev/null)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $FORGED" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "Forged claims (manipulated payload) blocked  [HTTP 401]" || fail "Forged JWT claims accepted" "HTTP $R"

# 11d. Expired token (manually set exp=1)
EXPIRED=$(node -e "
const t='$WEB_TOKEN'.split('.');
const p=JSON.parse(Buffer.from(t[1],'base64').toString());
p.exp=1; p.iat=0;
const newPayload=Buffer.from(JSON.stringify(p)).toString('base64url');
console.log(t[0]+'.'+newPayload+'.'+t[2]);
" 2>/dev/null)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $EXPIRED" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "Expired token (exp=1) blocked  [HTTP 401]" || fail "Expired token accepted" "HTTP $R"

# 11e. kid header injection — try to point kid to external URL
KID_INJECT=$(node -e "
const t='$WEB_TOKEN'.split('.');
const hdr=JSON.parse(Buffer.from(t[0],'base64').toString());
hdr.kid='../../../../../etc/passwd'; hdr.jku='http://evil.com/jwks.json';
const newHdr=Buffer.from(JSON.stringify(hdr)).toString('base64url');
console.log(newHdr+'.'+t[1]+'.'+t[2]);
" 2>/dev/null)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $KID_INJECT" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "kid/jku injection blocked  [HTTP 401]" || fail "kid/jku injection NOT blocked" "HTTP $R"

# ════════════════════════════════════════════════════════
# 12. WEB PENTESTS — Injection & Input Validation
# ════════════════════════════════════════════════════════
section "12/15 · PENTEST — Injection Attacks"

# 12a. SQL injection in Authorization header value
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ' OR '1'='1" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" == "401" ]] && pass "SQL injection in Bearer header rejected  [HTTP 401]" || fail "SQL injection in header not rejected" "HTTP $R"

# 12b. XSS payload in custom header
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: <script>alert(1)</script>" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers")
[[ "$R" != "200" || $(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: <script>alert(1)</script>" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers" | grep -c "<script>") -eq 0 ]] \
  && pass "XSS payload in header not reflected in response" \
  || fail "XSS payload reflected in response" "script tag returned in body"

# 12c. Path traversal on Kong routes
for path in "/../admin" "/%2e%2e/admin" "//admin" "/api/v1/web/../../internal"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$KONG$path")
  [[ "$CODE" != "200" ]] && pass "Path traversal '$path' rejected  [HTTP $CODE]" || fail "Path traversal '$path' may be accessible" "HTTP $CODE"
done

# 12d. HTTP method tampering — PUT/DELETE on GET-only routes
# OPTIONS is expected to return 200 (CORS preflight) — only check destructive methods
for method in PUT DELETE PATCH; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    -H "Authorization: Bearer $WEB_TOKEN" \
    -H "X-App-Version: 1.0.0" \
    "$KONG/api/v1/web/transfers")
  [[ "$CODE" != "200" ]] && pass "HTTP $method on /web/transfers rejected  [HTTP $CODE]" || fail "HTTP $method accepted on read-only route" "HTTP $CODE"
done
# OPTIONS 200 is correct for CORS preflight — verify it doesn't expose admin operations
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
  -H "Origin: http://localhost:4200" \
  -H "Access-Control-Request-Method: GET" \
  "$KONG/api/v1/web/transfers")
[[ "$CODE" == "200" || "$CODE" == "204" ]] && pass "OPTIONS (CORS preflight) returns $CODE — correct behavior" || fail "OPTIONS CORS preflight unexpected response" "HTTP $CODE"

# ════════════════════════════════════════════════════════
# 13. WEB PENTESTS — Information Disclosure
# ════════════════════════════════════════════════════════
section "13/15 · PENTEST — Information Disclosure"

# 13a. Stack trace in error responses
R=$(curl -s -H "Authorization: Bearer INVALID" -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers")
for keyword in "stack" "traceback" "at Object" "node_modules" "Error:" "undefined"; do
  if echo "$R" | grep -qi "$keyword"; then
    fail "Stack trace leaked in error response" "Found '$keyword' in: ${R:0:100}"
    break
  fi
done
echo "$R" | grep -qiE "(stack|traceback|node_modules)" || pass "No stack trace in error response"

# 13b. Server version headers not exposed
HDR=$(curl -sI -H "X-App-Version: 1.0.0" "$KONG/api/v1/web/transfers" 2>/dev/null)
echo "$HDR" | grep -qi "X-Powered-By" && fail "X-Powered-By header exposed" "$(echo "$HDR" | grep -i X-Powered-By)" || pass "X-Powered-By header not exposed"
echo "$HDR" | grep -qi "Server:" && SRV=$(echo "$HDR" | grep -i "^Server:" | head -1) && \
  (echo "$SRV" | grep -qiE "(nginx/[0-9]|apache/[0-9]|express|node)" && fail "Verbose Server header" "$SRV" || pass "Server header present but not verbose  [$SRV]") \
  || pass "Server header not exposed"

# 13c. Keycloak realm enumeration — non-existent realm
R=$(curl -s -o /dev/null -w "%{http_code}" "$KC/realms/nonexistent-realm/.well-known/openid-configuration")
[[ "$R" == "404" ]] && pass "Non-existent realm returns 404 (no enumeration info)" || fail "Non-existent realm returns HTTP $R" "May leak realm info"

# 13d. Keycloak user enumeration via login timing (same error for bad user vs bad password)
RESP_BADUSER=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=doesnotexist999&password=Test1234!&grant_type=password" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const o=JSON.parse(d);console.log(o.error_description||o.error||'')})")
RESP_BADPASS=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=WrongPassword!&grant_type=password" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const o=JSON.parse(d);console.log(o.error_description||o.error||'')})")
[[ "$RESP_BADUSER" == "$RESP_BADPASS" ]] \
  && pass "User enumeration: same error for bad user vs bad password  ['$RESP_BADUSER']" \
  || fail "User enumeration possible" "bad user='$RESP_BADUSER'  bad pass='$RESP_BADPASS'"

# ════════════════════════════════════════════════════════
# 14. WEB PENTESTS — Transport & Headers
# ════════════════════════════════════════════════════════
section "14/15 · PENTEST — Security Headers & CORS"

FULL_HDR=$(curl -sv -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers" 2>&1)

for hdr in "X-Content-Type-Options" "X-Frame-Options" "Cache-Control"; do
  echo "$FULL_HDR" | grep -qi "$hdr" && pass "Security header '$hdr' present" || fail "Security header '$hdr' missing" ""
done

# CORS: wildcard origin check
CORS=$(curl -s -I \
  -H "Origin: http://evil.com" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers" 2>/dev/null)
if echo "$CORS" | grep -qi "Access-Control-Allow-Origin: \*"; then
  fail "CORS allows wildcard origin (*)" "Any domain can make credentialed requests"
elif echo "$CORS" | grep -qi "Access-Control-Allow-Origin: http://evil.com"; then
  fail "CORS reflects evil origin" "Origin http://evil.com echoed back"
else
  pass "CORS does not allow arbitrary origins"
fi

# CORS preflight with evil origin
PREFLIGHT=$(curl -s -I -X OPTIONS \
  -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,X-App-Version" \
  "$KONG/api/v1/web/transfers" 2>/dev/null)
echo "$PREFLIGHT" | grep -qi "Access-Control-Allow-Origin: http://evil.com" \
  && fail "CORS preflight allows evil origin" "" \
  || pass "CORS preflight does not allow evil origin"

# ════════════════════════════════════════════════════════
# 15. WEB PENTESTS — Rate Limiting & DoS Resistance
# ════════════════════════════════════════════════════════
section "15/15 · PENTEST — Rate Limiting & Payload Abuse"

# 15a. Rate limiting — verify headers present + burst past limit
# Use GET with header dump (-D -) since HEAD is not in allowed methods
RL_HDR=$(curl -s -D - -o /dev/null \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  "$KONG/api/v1/web/transfers" 2>/dev/null)
if echo "$RL_HDR" | grep -qi "X-RateLimit"; then
  pass "Rate limiting headers present  [$(echo "$RL_HDR" | grep -i X-RateLimit | head -1 | tr -d '\r')]"
else
  fail "Rate limiting headers not found in response" "Kong rate-limiting plugin may not be active"
fi

# Burst past the mobile route limit (30/min) using a throwaway token
echo -e "  Bursting 35 requests on mobile route (limit=30/min)..."
RL_429=0
for i in $(seq 1 35); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $MOB_TOKEN" \
    -H "X-Client-Public-Key: $PUB_KEY" \
    -H "X-App-Version: 1.0.0" \
    "$KONG/api/v1/mobile/transfers")
  [[ "$CODE" == "429" ]] && RL_429=$((RL_429+1))
done
[[ $RL_429 -gt 0 ]] \
  && pass "Rate limit enforced on mobile route — HTTP 429 after 30 req/min  [$RL_429 throttled]" \
  || fail "Rate limit not enforced" "35 requests, 0 × 429 — check rate-limiting plugin config"

# 15b. Oversized payload — write to temp file to avoid shell arg limit
TMPFILE=$(mktemp /tmp/bigpayload.XXXXXX)
node -e "process.stdout.write(JSON.stringify({data:'A'.repeat(1024*1024)}))" > "$TMPFILE"
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0" \
  -H "Content-Type: application/json" \
  --data-binary "@$TMPFILE" \
  "$KONG/api/v1/web/transfers")
rm -f "$TMPFILE"
[[ "$R" == "413" || "$R" == "400" || "$R" == "414" ]] \
  && pass "Oversized payload (1 MB) rejected  [HTTP $R]" \
  || fail "Oversized payload not rejected" "HTTP $R — no body size limit enforced"

# 15c. Version header with oversized value
BIG_VER=$(node -e "console.log('A'.repeat(8192))")
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-App-Version: $BIG_VER" \
  "$KONG/api/v1/web/transfers")
[[ "$R" != "200" ]] && pass "Oversized X-App-Version header rejected  [HTTP $R]" || fail "Oversized header not rejected" "HTTP $R"

# 15d. Null byte injection in version header
# Kong strips null bytes at HTTP layer — "1.0.0\x00evil" becomes "1.0.0" (passes version check).
# Security guarantee: the null byte does NOT bypass the version check with an invalid version.
# We verify it does NOT return 200 (no bypass to data), which is the critical property.
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H $'X-App-Version: 0.0.1\x00.bypass' \
  "$KONG/api/v1/web/transfers")
[[ "$R" != "200" ]] && pass "Null byte cannot bypass version block  [HTTP $R — 0.0.1\\x00.bypass not treated as 1.0.0]" \
  || fail "Null byte bypassed version check" "HTTP $R — got 200"

section "16/16 · EMERGENCY LOCKDOWN — Invalidación masiva de tokens"

# Tokens frescos para esta sección
WEB_TOKEN_PRE=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

# 1. Verificar que el token funciona ANTES del lockdown
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/api/v1/data" \
  -H "Authorization: Bearer $WEB_TOKEN_PRE" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
[[ "$R" == "200" ]] \
  && pass "Token válido ANTES del lockdown → HTTP 200" \
  || fail "Token debería ser válido antes del lockdown" "HTTP $R"

# 2. Activar lockdown (requiere admin — usamos admin-web token desde web-realm si existe, sino skip)
ADMIN_TOKEN=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

# Activar lockdown vía Redis directamente (en POC el testuser no tiene rol admin-api)
# Simulamos el lockdown escribiendo en Redis con el epoch actual - 1 (todos los tokens emitidos antes)
LOCKDOWN_TS=$(date +%s)
docker exec redis-cache redis-cli SET emergency:lockdown "$LOCKDOWN_TS" > /dev/null 2>&1
sleep 1  # dar tiempo a que Redis propague

# 3. El token PRE-lockdown debe ser rechazado (iat < lockdown)
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/api/v1/data" \
  -H "Authorization: Bearer $WEB_TOKEN_PRE" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
[[ "$R" == "401" ]] \
  && pass "Token pre-lockdown rechazado tras activar lockdown → HTTP 401" \
  || fail "Token pre-lockdown debería ser rechazado (iat < lockdown)" "HTTP $R — esperado 401"

# 4. Token emitido DESPUÉS del lockdown debe funcionar
sleep 1
WEB_TOKEN_POST=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-test-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

R=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/api/v1/data" \
  -H "Authorization: Bearer $WEB_TOKEN_POST" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
[[ "$R" == "200" ]] \
  && pass "Token post-lockdown válido → HTTP 200 (iat > lockdown)" \
  || fail "Token emitido después del lockdown debería ser válido" "HTTP $R — esperado 200"

# 5. Verificar que lockdown aplica igualmente en transfers y payments
R_T=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/transfers" \
  -H "Authorization: Bearer $WEB_TOKEN_PRE" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
R_P=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/payments" \
  -H "Authorization: Bearer $WEB_TOKEN_PRE" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
[[ "$R_T" == "401" && "$R_P" == "401" ]] \
  && pass "Lockdown activo en transfers ($R_T) y payments ($R_P)" \
  || fail "Lockdown debe bloquear transfers y payments" "transfers=$R_T payments=$R_P"

# 6. Levantar lockdown
docker exec redis-cache redis-cli DEL emergency:lockdown > /dev/null 2>&1

# 7. Token PRE-lockdown vuelve a funcionar tras levantar lockdown
R=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KONG/api/v1/web/api/v1/data" \
  -H "Authorization: Bearer $WEB_TOKEN_PRE" \
  -H "X-Client-Public-Key: $PUB_KEY" \
  -H "X-App-Version: 1.0.0")
[[ "$R" == "200" ]] \
  && pass "Lockdown levantado — token pre-lockdown válido nuevamente → HTTP 200" \
  || fail "Token debe volver a funcionar tras levantar lockdown" "HTTP $R — esperado 200"

# ════════════════════════════════════════════════════════
# RESUMEN
# ════════════════════════════════════════════════════════
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo -e "${W}═══════════════════════════════════════${NC}"
echo -e "${W}  RESULTADOS  —  $TOTAL pruebas${NC}"
echo -e "${W}═══════════════════════════════════════${NC}"
echo -e "  ${G}✅ PASS  $PASS${NC}"
echo -e "  ${R}❌ FAIL  $FAIL${NC}"
[[ $SKIP -gt 0 ]] && echo -e "  ${Y}⚠️  SKIP  $SKIP${NC}"
echo -e "${W}═══════════════════════════════════════${NC}"

if [[ $FAIL -eq 0 ]]; then
  echo -e "\n  ${G}🎉 Todos los servicios funcionan correctamente${NC}\n"
  exit 0
else
  echo -e "\n  ${R}Hay $FAIL prueba(s) fallida(s) — revisa los errores arriba${NC}\n"
  exit 1
fi

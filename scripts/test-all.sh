#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  test-all.sh  — POC Security · Suite de Pruebas Completa
# ═══════════════════════════════════════════════════════════
set -uo pipefail

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
  python -c "
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
echo -e "\n  Obteniendo tokens..."
WEB_TOKEN=$(curl -s -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR:'+str(d.get('error',d))))")

MOB_TOKEN=$(curl -s -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR:'+str(d.get('error',d))))")

if [[ "$WEB_TOKEN" == ERROR* ]]; then fail "Token web-realm" "$WEB_TOKEN"
else pass "Token web-realm obtenido  [iss=web-realm]"; fi

if [[ "$MOB_TOKEN" == ERROR* ]]; then fail "Token mobile-realm" "$MOB_TOKEN"
else pass "Token mobile-realm obtenido  [iss=mobile-realm]"; fi

# Validar claims
WEB_AUD=$(echo "$WEB_TOKEN" | python -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
d=json.loads(base64.b64decode(t))
print(d.get('aud','missing'))
")
MOB_AUD=$(echo "$MOB_TOKEN" | python -c "
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

PUB_KEY=$(python -c "
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
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/web/api/v1/data")
check_jwe "api-node     · web-realm  → /api/v1/web/api/v1/data"    "$R" "data" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/mobile/api/v1/data")
check_jwe "api-node     · mobile-realm→ /api/v1/mobile/api/v1/data" "$R" "data" "mobile" 2>/dev/null || true

# transfers
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/web/transfers")
check_jwe "transfers    · web-realm  → /api/v1/web/transfers"    "$R" "transfers" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/mobile/transfers")
check_jwe "transfers    · mobile-realm→ /api/v1/mobile/transfers" "$R" "transfers" "mobile" 2>/dev/null || true

# payments
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/web/payments")
check_jwe "payments     · web-realm  → /api/v1/web/payments"    "$R" "payments" "web"    2>/dev/null || true

R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" "$KONG/api/v1/mobile/payments")
check_jwe "payments     · mobile-realm→ /api/v1/mobile/payments" "$R" "payments" "mobile" 2>/dev/null || true

# ════════════════════════════════════════════════════════
# 6. SEGURIDAD — Rechazos esperados
# ════════════════════════════════════════════════════════
section "6/7 · SEGURIDAD — Rechazos y Cross-Channel"

# Sin token
R=$(curl -s "$KONG/api/v1/web/transfers")
check_json_err "Sin token → 401"  "$R" "requerido"

# Token web en ruta mobile
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" \
       "$KONG/api/v1/mobile/transfers")
check_json_err "Token web-realm en /mobile/transfers → 401"  "$R" "inválido"

# Token mobile en ruta web
R=$(curl -s -H "Authorization: Bearer $MOB_TOKEN" -H "X-Client-Public-Key: $PUB_KEY" \
       "$KONG/api/v1/web/payments")
check_json_err "Token mobile-realm en /web/payments → 401"  "$R" "inválido"

# Sin X-Client-Public-Key
R=$(curl -s -H "Authorization: Bearer $WEB_TOKEN" "$KONG/api/v1/web/transfers")
check_json_err "Sin X-Client-Public-Key → 400"  "$R" "requerido"

# Token manipulado (firma inválida)
FAKE=$(echo "$WEB_TOKEN" | sed 's/\.\([^.]*\)$/\.INVALIDSIGNATURE/')
R=$(curl -s -H "Authorization: Bearer $FAKE" -H "X-Client-Public-Key: $PUB_KEY" \
       "$KONG/api/v1/web/transfers")
check_json_err "JWT con firma inválida → 401"  "$R" "inválido"

# ════════════════════════════════════════════════════════
# 7. ENDPOINTS POST — Crear recursos
# ════════════════════════════════════════════════════════
section "7/7 · ENDPOINTS POST — Creación de Recursos"

# POST transfer (web)
R=$(curl -s -X POST \
       -H "Authorization: Bearer $WEB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "Content-Type: application/json" \
       -d '{"amount":500,"to":"ACC-9988","memo":"Test transfer"}' \
       "$KONG/api/v1/web/transfers")
check_jwe "POST /web/transfers  → crear transferencia web"  "$R" "transfers" "web" 2>/dev/null || true

# POST transfer (mobile)
R=$(curl -s -X POST \
       -H "Authorization: Bearer $MOB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "Content-Type: application/json" \
       -d '{"amount":200,"to":"ACC-1122","memo":"Test mobile"}' \
       "$KONG/api/v1/mobile/transfers")
check_jwe "POST /mobile/transfers → crear transferencia mobile" "$R" "transfers" "mobile" 2>/dev/null || true

# POST payment (web)
R=$(curl -s -X POST \
       -H "Authorization: Bearer $WEB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "Content-Type: application/json" \
       -d '{"amount":99.99,"method":"card","merchant":"Test Corp"}' \
       "$KONG/api/v1/web/payments")
check_jwe "POST /web/payments   → crear pago web"           "$R" "payments" "web" 2>/dev/null || true

# POST payment (mobile)
R=$(curl -s -X POST \
       -H "Authorization: Bearer $MOB_TOKEN" \
       -H "X-Client-Public-Key: $PUB_KEY" \
       -H "Content-Type: application/json" \
       -d '{"amount":49.99,"method":"ach","merchant":"Utility"}' \
       "$KONG/api/v1/mobile/payments")
check_jwe "POST /mobile/payments → crear pago mobile"       "$R" "payments" "mobile" 2>/dev/null || true

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

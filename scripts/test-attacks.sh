#!/usr/bin/env bash
# test-attacks.sh — pruebas de ataques negativos
# Verifica que cada control de seguridad bloquea el ataque correspondiente.
# Ejecutar con: bash scripts/test-attacks.sh
# Requiere: stack completo levantado (docker compose up -d)

set -uo pipefail

KC="http://localhost:8080"
KONG="http://localhost:8000"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;90m'; BOLD='\033[1;37m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0

pass() { PASS=$((PASS+1)); echo -e "  ${GREEN}✅ PASS${NC}  $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}❌ FAIL${NC}  $1${2:+ — }${2:-}"; }
skip() { SKIP=$((SKIP+1)); echo -e "  ${YELLOW}⏭  SKIP${NC}  $1 — $2"; }
info() { echo -e "  ${GRAY}ℹ  $1${NC}"; }
section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

# ── SETUP ─────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  POC Security — Attack Repudiation Tests${NC}"
echo -e "${BOLD}  Target: $KONG${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "\n${GRAY}Preparando tokens...${NC}"

WEB_TOKEN=$(curl -sf -X POST "$KC/realms/web-realm/protocol/openid-connect/token" \
  -d "client_id=web-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])") || {
  echo -e "${RED}ERROR: No se pudo obtener token web. ¿Está el stack levantado?${NC}"; exit 1; }

MOB_TOKEN=$(curl -sf -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])") || {
  echo -e "${RED}ERROR: No se pudo obtener token mobile.${NC}"; exit 1; }

echo -e "\n${GRAY}Reiniciando servicios para limpiar stores en memoria...${NC}"
docker compose restart api-node transfers-service payments-service 2>/dev/null

# Esperar readiness real: usar request autenticada y esperar hasta que llegue
# una respuesta que NO sea 502/000 (502 = servicio no listo o Odoo no conectado)
echo -e "${GRAY}Esperando readiness de servicios (máx 60s)...${NC}"
READY=0
for i in $(seq 1 30); do
  # Sin X-Client-Public-Key: llega hasta el handler → 400, sin crear binding
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $WEB_TOKEN" \
    "$KONG/api/v1/web/transfers" 2>/dev/null)
  if [ "$CODE" != "502" ] && [ "$CODE" != "000" ]; then
    READY=1
    echo -e "${GRAY}Servicios listos (HTTP $CODE) después de ${i}x2s${NC}"
    break
  fi
  sleep 2
done
[ "$READY" -eq 0 ] && echo -e "${YELLOW}⚠  Readiness timeout — continuando de todas formas${NC}"

# Extraer SUB del token mobile (para Odoo)
MOB_SUB=$(echo "$MOB_TOKEN" | python3 -c "
import sys,base64,json
t=sys.stdin.read().strip().split('.')[1]
t+='=='*(4-len(t)%4)
print(json.loads(base64.b64decode(t))['sub'])
")

# Generar DOS claves RSA distintas (para test de key substitution)
KEYS=$(python3 -c "
import json,base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
def make_key():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    pub = key.public_key().public_numbers()
    def b64u(x): return base64.urlsafe_b64encode(x.to_bytes((x.bit_length()+7)//8,'big')).rstrip(b'=').decode()
    jwk = {'kty':'RSA','use':'enc','alg':'RSA-OAEP-256','n':b64u(pub.n),'e':b64u(pub.e)}
    return base64.b64encode(json.dumps(jwk).encode()).decode()
print(make_key())
print(make_key())
")
KEY_A=$(echo "$KEYS" | sed -n '1p')
KEY_B=$(echo "$KEYS" | sed -n '2p')
info "KEY_A generada (len=${#KEY_A}), KEY_B generada (len=${#KEY_B})"
info "MOB_SUB: ${MOB_SUB:0:12}..."

# ── TEST 1: HEADER DISCLOSURE ─────────────────────────────────────────────────
section "1/9 · Header Disclosure — X-Powered-By / ETag / Cache-Control"

HEADERS=$(curl -s -v \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  "$KONG/api/v1/web/transfers" 2>&1)

if echo "$HEADERS" | grep -qi "x-powered-by"; then
  fail "X-Powered-By ausente" "Header todavía presente"
else
  pass "X-Powered-By eliminado"
fi

if echo "$HEADERS" | grep -qi "^< etag"; then
  fail "ETag ausente" "Header todavía presente"
else
  pass "ETag eliminado"
fi

if echo "$HEADERS" | grep -qi "cache-control: no-store"; then
  pass "Cache-Control: no-store presente"
else
  fail "Cache-Control: no-store" "Header ausente o incorrecto"
fi

# ── TEST 2: JWE KEY SUBSTITUTION ──────────────────────────────────────────────
section "2/9 · JWE Key Substitution — pubkey binding"

# Primer request con KEY_A — registra el binding para este sub
R1=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  "$KONG/api/v1/mobile/transfers")
info "Request con KEY_A → HTTP $R1 (registra binding)"

# Segundo request con KEY_B mismo token/sub → debe fallar
R2=$(curl -s \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_B" \
  "$KONG/api/v1/mobile/transfers")
CODE2=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_B" \
  "$KONG/api/v1/mobile/transfers")

if [ "$CODE2" = "403" ] && echo "$R2" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'Clave' in d.get('error','') else 1)" 2>/dev/null; then
  pass "Key substitution bloqueada → 403 con clave distinta"
  info "Response: $(echo "$R2" | python3 -c 'import sys,json; print(json.load(sys.stdin))' 2>/dev/null)"
else
  fail "Key substitution bloqueada" "Esperado 403, recibido $CODE2 — $(echo "$R2" | head -c 120)"
fi

# Verificar que KEY_A sigue funcionando (mismo binding)
R3=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  "$KONG/api/v1/mobile/transfers")
if [ "$R3" = "200" ]; then
  pass "KEY_A original sigue funcionando → 200 (binding íntegro)"
else
  fail "KEY_A original" "Esperado 200, recibido $R3"
fi

# ── TEST 3: API REPLAY ────────────────────────────────────────────────────────
section "3/9 · API Replay — X-Idempotency-Key"

# Obtener token fresco para este test (distinto sub evita colisión de binding con test 2)
IDEM_KEY="replay-test-$(date +%s%N)"

# Primer POST — procesa normalmente
R_FIRST=$(curl -s \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: $IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"ACC-REPLAY","memo":"test replay"}' \
  "$KONG/api/v1/web/transfers")
CODE_FIRST=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: $IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"ACC-REPLAY","memo":"test replay"}' \
  "$KONG/api/v1/web/transfers")
info "Primer POST → HTTP $CODE_FIRST"

# Segundo POST con mismo IDEM_KEY — debe ser replay
REPLAY_HEADERS=$(curl -sv \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: $IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"ACC-REPLAY","memo":"test replay"}' \
  "$KONG/api/v1/web/transfers" 2>&1)
REPLAY_CODE=$(echo "$REPLAY_HEADERS" | grep "< HTTP/" | grep -oE "[0-9]{3}" | head -1)

if echo "$REPLAY_HEADERS" | grep -qi "x-idempotency-replayed: true"; then
  pass "Replay detectado → X-Idempotency-Replayed: true (HTTP $REPLAY_CODE)"
else
  fail "Replay detectado" "Header X-Idempotency-Replayed ausente — HTTP $REPLAY_CODE"
fi

# ── TEST 4: MISSING IDEMPOTENCY KEY ───────────────────────────────────────────
section "4/9 · POST sin X-Idempotency-Key"

R4=$(curl -s \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"ACC-001"}' \
  "$KONG/api/v1/web/transfers")
CODE4=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"ACC-001"}' \
  "$KONG/api/v1/web/transfers")

if [ "$CODE4" = "400" ] && echo "$R4" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'Idempotency' in d.get('error','') else 1)" 2>/dev/null; then
  pass "Sin X-Idempotency-Key → 400 requerido"
else
  fail "Sin X-Idempotency-Key" "Esperado 400, recibido $CODE4 — $(echo "$R4" | head -c 100)"
fi

# ── TEST 5: ODOO AUTHZ BYPASS ─────────────────────────────────────────────────
section "5/9 · Odoo AuthZ Bypass — cliente desactivado"

# Desactivar el cliente en Odoo
ODOO_RESULT=$(docker exec odoo-server python3 -c "
import xmlrpc.client, sys
url = 'http://localhost:8069'
db  = 'pocdb'
try:
    uid = xmlrpc.client.ServerProxy(url+'/xmlrpc/2/common').authenticate(db,'admin','admin',{})
    models = xmlrpc.client.ServerProxy(url+'/xmlrpc/2/object')
    ids = models.execute_kw(db,uid,'admin','x_api_clientes','search',[[['sub','=','$MOB_SUB']]],{'context':{'active_test':False}})
    if not ids:
        print('NOT_FOUND')
        sys.exit(0)
    models.execute_kw(db,uid,'admin','x_api_clientes','write',[ids,{'active':False}])
    print('DEACTIVATED:' + str(ids[0]))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)

if echo "$ODOO_RESULT" | grep -q "DEACTIVATED"; then
  RECORD_ID=$(echo "$ODOO_RESULT" | grep -oE '[0-9]+$')
  info "Cliente desactivado en Odoo (id=$RECORD_ID)"

  # Obtener token fresco (el anterior podría estar cacheado)
  MOB_TOKEN2=$(curl -sf -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
    -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  R5=$(curl -s \
    -H "Authorization: Bearer $MOB_TOKEN2" \
    -H "X-Client-Public-Key: $KEY_A" \
    "$KONG/api/v1/mobile/api/v1/data")
  CODE5=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $MOB_TOKEN2" \
    -H "X-Client-Public-Key: $KEY_A" \
    "$KONG/api/v1/mobile/api/v1/data")

  # Reactivar cliente antes de evaluar (cleanup siempre)
  docker exec odoo-server python3 -c "
import xmlrpc.client
url='http://localhost:8069'; db='pocdb'
uid = xmlrpc.client.ServerProxy(url+'/xmlrpc/2/common').authenticate(db,'admin','admin',{})
xmlrpc.client.ServerProxy(url+'/xmlrpc/2/object').execute_kw(db,uid,'admin','x_api_clientes','write',[[$RECORD_ID],{'active':True}])
" 2>/dev/null
  info "Cliente reactivado en Odoo"

  if [ "$CODE5" = "403" ]; then
    pass "Odoo AuthZ bloquea cliente desactivado → 403"
    info "Response: $(echo "$R5" | head -c 120)"
  else
    fail "Odoo AuthZ bypass" "Esperado 403, recibido $CODE5 — $(echo "$R5" | head -c 120)"
  fi
elif echo "$ODOO_RESULT" | grep -q "NOT_FOUND"; then
  skip "Odoo AuthZ" "Sub $MOB_SUB no encontrado en x_api_clientes — ejecutar setup primero"
else
  skip "Odoo AuthZ" "Error accediendo a Odoo: $ODOO_RESULT"
fi

# ── TEST 6: AMOUNT LIMIT ──────────────────────────────────────────────────────
section "6/9 · Monto fuera de límite — transfers > \$10,000"

R6=$(curl -s \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: limit-test-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '{"amount":99999,"to":"ACC-LIMIT","memo":"over limit"}' \
  "$KONG/api/v1/web/transfers")
CODE6=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: limit-test2-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '{"amount":99999,"to":"ACC-LIMIT","memo":"over limit"}' \
  "$KONG/api/v1/web/transfers")

if [ "$CODE6" = "422" ]; then
  pass "Amount limit bloqueado → 422 (amount=99999 > 10000)"
  info "Response: $(echo "$R6" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("error","?"))' 2>/dev/null)"
else
  fail "Amount limit" "Esperado 422, recibido $CODE6 — $(echo "$R6" | head -c 100)"
fi

# Verificar que monto válido pasa
R6B=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: limit-valid-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '{"amount":500,"to":"ACC-001"}' \
  "$KONG/api/v1/web/transfers")
if [ "$R6B" = "200" ]; then
  pass "Monto válido (\$500) pasa → 200"
else
  fail "Monto válido" "Esperado 200, recibido $R6B"
fi

# ── TEST 7: INVALID PAYMENT METHOD ───────────────────────────────────────────
section "7/9 · Método de pago inválido — payments method=crypto"

R7=$(curl -s \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: method-test-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"method":"crypto","merchant":"Bitcoin Shop"}' \
  "$KONG/api/v1/web/payments")
CODE7=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  -H "X-Idempotency-Key: method-test2-$(date +%s%N)" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"method":"crypto","merchant":"Bitcoin Shop"}' \
  "$KONG/api/v1/web/payments")

if [ "$CODE7" = "422" ]; then
  pass "Método inválido bloqueado → 422 (method=crypto)"
  info "Response: $(echo "$R7" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("error","?"))' 2>/dev/null)"
else
  fail "Método inválido" "Esperado 422, recibido $CODE7 — $(echo "$R7" | head -c 100)"
fi

# Verificar métodos válidos
for METHOD in "card" "ach" "wire"; do
  R7M=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer $WEB_TOKEN" \
    -H "X-Client-Public-Key: $KEY_A" \
    -H "X-Idempotency-Key: method-${METHOD}-$(date +%s%N)" \
    -H "Content-Type: application/json" \
    -d "{\"amount\":100,\"method\":\"$METHOD\",\"merchant\":\"Test\"}" \
    "$KONG/api/v1/web/payments")
  if [ "$R7M" = "200" ]; then
    pass "Método '$METHOD' aceptado → 200"
  else
    fail "Método '$METHOD'" "Esperado 200, recibido $R7M"
  fi
done

# ── TEST 8: CROSS-CHANNEL ATTACK ──────────────────────────────────────────────
section "8/9 · Cross-Channel Attack — token web en endpoint mobile"

R8A=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $WEB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  "$KONG/api/v1/mobile/transfers")
if [ "$R8A" = "401" ]; then
  pass "Token web-realm rechazado en /mobile/transfers → 401"
else
  fail "Cross-channel (web→mobile)" "Esperado 401, recibido $R8A"
fi

R8B=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $MOB_TOKEN" \
  -H "X-Client-Public-Key: $KEY_A" \
  "$KONG/api/v1/web/payments")
if [ "$R8B" = "401" ]; then
  pass "Token mobile-realm rechazado en /web/payments → 401"
else
  fail "Cross-channel (mobile→web)" "Esperado 401, recibido $R8B"
fi

# ── TEST 9: RATE LIMITING ─────────────────────────────────────────────────────
section "9/9 · Rate Limiting — flood de 35 requests (límite mobile: 30/min)"

info "Enviando 35 requests con mismo token mobile... (puede tardar ~15s)"

# Token fresco para este test
MOB_TOKEN3=$(curl -sf -X POST "$KC/realms/mobile-realm/protocol/openid-connect/token" \
  -d "client_id=mobile-app-client&username=testuser&password=Test1234!&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

RATE_RESULTS=()
for i in $(seq 1 35); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $MOB_TOKEN3" \
    -H "X-Client-Public-Key: $KEY_A" \
    "$KONG/api/v1/mobile/transfers" &)
  RATE_RESULTS+=("$CODE")
done
wait

# Dar tiempo a que terminen todos los requests en background
sleep 4

# Re-ejecutar síncronamente para capturar resultados reales
COUNT_429=0
COUNT_200=0
COUNT_OTHER=0
for i in $(seq 1 35); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $MOB_TOKEN3" \
    -H "X-Client-Public-Key: $KEY_A" \
    "$KONG/api/v1/mobile/transfers")
  case "$CODE" in
    200) COUNT_200=$((COUNT_200+1)) ;;
    429) COUNT_429=$((COUNT_429+1)) ;;
    *)   COUNT_OTHER=$((COUNT_OTHER+1)) ;;
  esac
done

info "Resultados: 200=$COUNT_200 · 429=$COUNT_429 · otros=$COUNT_OTHER"
if [ "$COUNT_429" -gt 0 ]; then
  pass "Rate limiting activo → $COUNT_429 requests bloqueadas con 429"
else
  fail "Rate limiting" "Ningún 429 recibido en 35 requests — ¿límite no alcanzado o policy=local reiniciada?"
fi

# ── RESUMEN ────────────────────────────────────────────────────────────────────
TOTAL=$((PASS+FAIL+SKIP))
echo -e "\n${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESULTADO ATAQUES  —  $TOTAL pruebas${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✅ PASS  $PASS${NC}"
echo -e "  ${RED}❌ FAIL  $FAIL${NC}"
echo -e "  ${YELLOW}⏭  SKIP  $SKIP${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}\n"

[ "$FAIL" -eq 0 ] && echo -e "  ${GREEN}🛡️  Todos los controles de seguridad funcionan correctamente${NC}\n"
[ "$FAIL" -gt 0 ] && echo -e "  ${RED}⚠️  $FAIL controles fallaron — revisar implementación${NC}\n"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0

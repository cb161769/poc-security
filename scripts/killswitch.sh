#!/bin/bash
# killswitch.sh

if [ "$1" = "ON" ]; then
    echo "🚨 BLOQUEO TOTAL ACTIVADO"
    docker exec kong-gateway curl -s -X POST http://localhost:8001/plugins \
      -d "name=request-termination" \
      -d "config.status_code=503" \
      -d "config.message='SISTEMA EN MANTENIMIENTO DE EMERGENCIA'"
elif [ "$1" = "OFF" ]; then
    echo "✅ SERVICIOS RESTAURADOS"
    ID=$(docker exec kong-gateway curl -s http://localhost:8001/plugins | grep -oP '"id":"\K[^"]+(?=","name":"request-termination")')
    docker exec kong-gateway curl -s -X DELETE http://localhost:8001/plugins/$ID
fiok
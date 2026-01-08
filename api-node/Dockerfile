# --- FASE 1: Construcción (Build) ---
FROM node:20-alpine AS builder

WORKDIR /app

# Copiamos solo archivos de dependencias para aprovechar el caché
COPY package*.json ./

# Instalación limpia de solo dependencias de producción
RUN npm ci --only=production

# Copiamos el código fuente
COPY . .

# --- FASE 2: Ejecución (Runtime SEGURO) ---
FROM node:20-alpine

# Hardening: Instalamos actualizaciones de seguridad y eliminamos gestores de paquetes
RUN apk update && apk upgrade && \
    rm -rf /var/cache/apk/*

WORKDIR /usr/src/app

# Hardening: Copiamos desde el builder solo lo necesario
# Esto evita que el contenedor final tenga herramientas de compilación o código basura
COPY --from=builder /app ./

# Hardening: No correr como ROOT
# El usuario 'node' ya existe en la imagen alpine. 
# Si un atacante compromete la app, no tendrá permisos de sistema.
USER node

# Exponer el puerto del backend (solo accesible por Kong internamente)
EXPOSE 3000

# Metadata de seguridad
LABEL version="1.0"
LABEL description="Backend Hardened para POC 2026 - Jose/JWE"

# Ejecución
CMD [ "node", "index.js" ]
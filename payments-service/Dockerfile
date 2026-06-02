FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

FROM node:20-alpine
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
COPY --from=builder /app ./
COPY index.js .
USER node
EXPOSE 3002
CMD ["node", "index.js"]

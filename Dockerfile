# ── Stage 1: install deps ──────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --only=production

# ── Stage 2: runtime ────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Non-root for security
RUN addgroup -S cloudvault && adduser -S cloudvault -G cloudvault

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Koyeb sets PORT automatically; default to 8080
ENV PORT=8080
ENV NODE_ENV=production

USER cloudvault
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["node", "index.js"]

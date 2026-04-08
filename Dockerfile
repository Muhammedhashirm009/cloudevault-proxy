# ── Stage 1: Build Go binary ───────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cloudvault-proxy .

# ── Stage 2: Minimal runtime ──────────────────────────────────────────
FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /app

# Non-root for security
RUN addgroup -S cloudvault && adduser -S cloudvault -G cloudvault

COPY --from=builder /build/cloudvault-proxy .

# Koyeb sets PORT automatically; default to 8080
ENV PORT=8080

USER cloudvault
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["./cloudvault-proxy"]

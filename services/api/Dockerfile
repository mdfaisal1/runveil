# syntax=docker/dockerfile:1

# ---- build stage ----
# Build context must be the REPO ROOT (single Go module), e.g.:
#   docker build -f services/api/Dockerfile -t runveil-api .
FROM golang:1.23-alpine AS build
WORKDIR /src

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Build the API binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./services/api

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 runveil
USER runveil
WORKDIR /app
COPY --from=build /out/api /app/api

EXPOSE 8080

# Postgres is host-installed, not in Docker. To reach it from this container,
# run with RUNTIME_NET=internal so the API uses PG_URL_INTERNAL
# (host.docker.internal:5432). Example:
#   docker run --rm -p 8080:8080 \
#     -e RUNTIME_NET=internal \
#     -e PG_URL_INTERNAL='postgres://runveil:runveil@host.docker.internal:5432/runveil?sslmode=disable' \
#     runveil-api
# On Linux, add: --add-host=host.docker.internal:host-gateway
ENTRYPOINT ["/app/api"]

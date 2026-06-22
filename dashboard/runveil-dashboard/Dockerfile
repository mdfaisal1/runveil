# syntax=docker/dockerfile:1

# ---- build stage ----
# Build context is this directory (dashboard/runveil-dashboard), e.g.:
#   docker build -t runveil-ui dashboard/runveil-dashboard
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- runtime stage ----
FROM nginx:1.27-alpine
# Angular 19 application builder emits static assets under dist/<name>/browser.
COPY --from=build /app/dist/runveil-dashboard/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
# The nginx config proxies /v1 and /health to the API. Override the upstream at
# runtime with -e API_UPSTREAM=http://host.docker.internal:8080 (default), e.g.:
#   docker run --rm -p 4200:80 \
#     -e API_UPSTREAM=http://host.docker.internal:8080 runveil-ui
# On Linux, add: --add-host=host.docker.internal:host-gateway
ENV API_UPSTREAM=http://host.docker.internal:8080
CMD ["/bin/sh", "-c", "envsubst '$API_UPSTREAM' < /etc/nginx/conf.d/default.conf > /tmp/default.conf && cp /tmp/default.conf /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]

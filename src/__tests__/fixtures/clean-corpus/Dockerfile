# Hardened Dockerfile — should produce no Error/Warning findings.
FROM node:20.11.1-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

RUN addgroup --system app && adduser --system --ingroup app app \
    && chown -R app:app /app
USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD ["node", "healthcheck.js"]

CMD ["node", "server.js"]

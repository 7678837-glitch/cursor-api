FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json VERSION ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
ARG GIT_COMMIT=unknown
ENV TZ=UTC \
    NODE_ENV=production \
    GIT_COMMIT=${GIT_COMMIT}
WORKDIR /app
RUN useradd --system --uid 1001 --home-dir /app --shell /usr/sbin/nologin app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY public ./public
COPY VERSION ./
RUN mkdir -p /app/data && chown -R app:app /app
USER app
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "import('./dist/config.js').then(({loadConfig})=>{const c=loadConfig();return fetch('http://'+(c.gatewayHost==='0.0.0.0'?'127.0.0.1':c.gatewayHost==='::'?'[::1]':c.gatewayHost.includes(':')?'['+c.gatewayHost+']':c.gatewayHost)+':'+c.gatewayPort+'/health')}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
